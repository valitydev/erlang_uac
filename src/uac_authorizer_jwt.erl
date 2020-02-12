-module(uac_authorizer_jwt).

%%
-export([init/1]).
-export([get_child_spec/0]).

% TODO
% Extend interface to support proper keystore manipulation

-export([configure/1]).
-export([issue/5]).
-export([issue/6]).
-export([verify/2]).

%%

-export([get_subject_id/1]).
-export([get_claims/1]).
-export([get_claim/2]).
-export([get_claim/3]).

%%

-include_lib("jose/include/jose_jwk.hrl").
-include_lib("jose/include/jose_jwt.hrl").

-type keyname()      :: term().
-type kid()          :: binary().
-type key()          :: #jose_jwk{}.
-type token()        :: binary().
-type claims()       :: #{binary() => term()}.
-type subject()      :: {subject_id(), uac_acl:t()}.
-type subject_id()   :: binary().
-type t()            :: {id(), subject(), claims()}.
-type domain_name()  :: binary().
-type domains()      :: #{domain_name() => uac_acl:t()}.
-type expiration()        ::
    {lifetime, Seconds :: pos_integer()} |
    {deadline, UnixTs :: pos_integer()}  |
    unlimited.
-type id() :: binary().

-export_type([t/0]).
-export_type([subject/0]).
-export_type([claims/0]).
-export_type([token/0]).
-export_type([expiration/0]).
-export_type([domain_name/0]).
-export_type([domains/0]).
%%

-type options() :: #{
    %% The set of keys used to sign issued tokens and verify signatures on such
    %% tokens.
    keyset => keyset()
}.

-export_type([options/0]).

-type keyset() :: #{
    keyname() => keysource()
}.

-type keysource() ::
    {pem_file, file:filename()}.

-spec get_child_spec() ->
    [supervisor:child_spec()].

get_child_spec() ->
    [#{
        id => ?MODULE,
        start => {supervisor, start_link, [?MODULE, []]},
        type => supervisor
    }].

-spec init([]) ->
    {ok, {supervisor:sup_flags(), [supervisor:child_spec()]}}.

init([]) ->
    ok = create_table(),
    {ok, {#{}, []}}.

%%

-spec configure(options()) ->
    ok.
configure(Options) ->
    Keyset = parse_options(Options),
    _ = maps:map(fun ensure_store_key/2, Keyset),
    ok.

parse_options(Options) ->
    Keyset = maps:get(keyset, Options, #{}),
    _ = is_map(Keyset) orelse exit({invalid_option, keyset, Keyset}),
    _ = genlib_map:foreach(
        fun (K, V) ->
            is_keysource(V) orelse exit({invalid_option, K, V})
        end,
        Keyset
    ),
    Keyset.

is_keysource({pem_file, Fn}) ->
    is_list(Fn) orelse is_binary(Fn);
is_keysource(_) ->
    false.

ensure_store_key(Keyname, Source) ->
    case store_key(Keyname, Source) of
        ok ->
            ok;
        {error, Reason} ->
            exit({import_error, Keyname, Source, Reason})
    end.

%%

-spec store_key(keyname(), {pem_file, file:filename()}) ->
    ok | {error, file:posix() | {unknown_key, _}}.

store_key(Keyname, {pem_file, Filename}) ->
    store_key(Keyname, {pem_file, Filename}, #{
        kid => fun derive_kid_from_public_key_pem_entry/1
    }).

derive_kid_from_public_key_pem_entry(JWK) ->
    JWKPublic = jose_jwk:to_public(JWK),
    {_Module, PublicKey} = JWKPublic#jose_jwk.kty,
    {_PemEntry, Data, _} = public_key:pem_entry_encode('SubjectPublicKeyInfo', PublicKey),
    base64url:encode(crypto:hash(sha256, Data)).

-type store_opts() :: #{
    kid => fun ((key()) -> kid())
}.

-spec store_key(keyname(), {pem_file, file:filename()}, store_opts()) ->
    ok | {error, file:posix() | {unknown_key, _}}.

store_key(Keyname, {pem_file, Filename}, Opts) ->
    case jose_jwk:from_pem_file(Filename) of
        JWK = #jose_jwk{} ->
            Key = construct_key(derive_kid(JWK, Opts), JWK),
            ok = insert_key(Keyname, Key);
        Error = {error, _} ->
            Error
    end.

derive_kid(JWK, #{kid := DeriveFun}) when is_function(DeriveFun, 1) ->
    DeriveFun(JWK).

construct_key(KID, JWK) ->
    Signer = try jose_jwk:signer(JWK)   catch error:_ -> undefined end,
    Verifier = try jose_jwk:verifier(JWK) catch error:_ -> undefined end,
    #{
        jwk        => JWK,
        kid        => KID,
        signer     => Signer,
        can_sign   => Signer /= undefined,
        verifier   => Verifier,
        can_verify => Verifier /= undefined
    }.

%%

-spec issue(id(), expiration(), subject(), claims(), keyname()) ->
    {ok, token()} |
    {error, nonexistent_key} |
    {error, {invalid_signee, Reason :: atom()}}.

issue(JTI, Expiration, {SubjectID, ACL}, Claims, Signee) ->
    Domain = uac_conf:get_domain_name(),
    DomainRoles = case ACL of
        undefined -> #{};
        ACL -> #{Domain => ACL}
    end,
    issue(JTI, Expiration, SubjectID, DomainRoles, Claims, Signee).

-spec issue(id(), expiration(), subject_id(), domains(), claims(), keyname()) ->
    {ok, token()} |
    {error, nonexistent_key} |
    {error, {invalid_signee, Reason :: atom()}}.

issue(JTI, Expiration, SubjectID, DomainRoles, Claims, Signee) ->
    case try_get_key_for_sign(Signee) of
        {ok, Key} ->
            FinalClaims = construct_final_claims(SubjectID, DomainRoles, Claims, Expiration, JTI),
            sign(Key, FinalClaims);
        {error, Error} ->
            {error, Error}
    end.

try_get_key_for_sign(Keyname) ->
    case get_key_by_name(Keyname) of
        #{can_sign := true} = Key ->
            {ok, Key};
        #{} ->
            {error, {invalid_signee, signing_not_allowed}};
        undefined ->
            {error, nonexistent_key}
    end.

construct_final_claims(SubjectID, DomainRoles, Claims, Expiration, JTI) ->
    maps:merge(
        Claims#{
            <<"jti">> => JTI,
            <<"sub">> => SubjectID,
            <<"exp">> => get_expires_at(Expiration)
        },
        encode_roles(DomainRoles)
    ).

get_expires_at({lifetime, Lt}) ->
    genlib_time:unow() + Lt;
get_expires_at({deadline, Dl}) ->
    Dl;
get_expires_at(unlimited) ->
    0.

sign(#{kid := KID, jwk := JWK, signer := #{} = JWS}, Claims) ->
    JWT = jose_jwt:sign(JWK, JWS#{<<"kid">> => KID}, Claims),
    {_Modules, Token} = jose_jws:compact(JWT),
    {ok, Token}.

%%

-spec verify(token(), uac:verification_opts()) ->
    {ok, t()} |
    {error,
        {invalid_token,
            badarg |
            {badarg, term()} |
            {missing, atom()} |
            expired |
            {malformed_acl, term()}
        } |
        {nonexistent_key, kid()} |
        {invalid_operation, term()} |
        invalid_signature
    }.

verify(Token, VerificationOpts) ->
    try
        {_, ExpandedToken} = jose_jws:expand(Token),
        #{<<"protected">> := ProtectedHeader} = ExpandedToken,
        Header = base64url_to_map(ProtectedHeader),
        Alg = get_alg(Header),
        KID = get_kid(Header),
        verify(KID, Alg, ExpandedToken, VerificationOpts)
    catch
        %% from get_alg and get_kid
        throw:Reason ->
            {error, Reason};
        %% TODO we're losing error information here, e.g. stacktrace
        error:badarg = Reason ->
            {error, {invalid_token, Reason}};
        error:{badarg, _} = Reason ->
            {error, {invalid_token, Reason}};
        error:Reason ->
            {error, {invalid_token, Reason}}
    end.

verify(KID, Alg, ExpandedToken, VerificationOpts) ->
    case get_key_by_kid(KID) of
        #{jwk := JWK, verifier := Algs} ->
            _ = lists:member(Alg, Algs) orelse throw({invalid_operation, Alg}),
            verify(JWK, ExpandedToken, VerificationOpts);
        undefined ->
            {error, {nonexistent_key, KID}}
    end.

verify(JWK, ExpandedToken, VerificationOpts) ->
    case jose_jwt:verify(JWK, ExpandedToken) of
        {true, #jose_jwt{fields = Claims}, _JWS} ->
            {KeyMeta, Claims1} = validate_claims(Claims, VerificationOpts),
            get_result(KeyMeta, decode_roles(Claims1));
        {false, _JWT, _JWS} ->
            {error, invalid_signature}
    end.

validate_claims(Claims, VerificationOpts) ->
    validate_claims(Claims, get_validators(), VerificationOpts, #{}).

validate_claims(Claims, [{Name, Claim, Validator} | Rest], VerificationOpts, Acc) ->
    V = Validator(Name, maps:get(Claim, Claims, undefined), VerificationOpts),
    validate_claims(maps:without([Claim], Claims), Rest, VerificationOpts, Acc#{Name => V});
validate_claims(Claims, [], _, Acc) ->
    {Acc, Claims}.

get_result(KeyMeta, {Roles, Claims}) ->
    #{token_id := TokenID, subject_id := SubjectID} = KeyMeta,
    try
        Subject = {SubjectID, try_decode_roles(Roles)},
        {ok, {TokenID, Subject, Claims}}
    catch
        error:{badarg, _} = Reason ->
            throw({invalid_token, {malformed_acl, Reason}})
    end.

try_decode_roles(undefined) ->
    undefined;
try_decode_roles(Roles0) ->
    uac_acl:decode(Roles0).

get_kid(#{<<"kid">> := KID}) when is_binary(KID) ->
    KID;
get_kid(#{}) ->
    throw({invalid_token, {missing, kid}}).

get_alg(#{<<"alg">> := Alg}) when is_binary(Alg) ->
    Alg;
get_alg(#{}) ->
    throw({invalid_token, {missing, alg}}).

%%

get_validators() ->
    [
        {token_id   , <<"jti">> , fun check_presence/3},
        {subject_id , <<"sub">> , fun check_presence/3},
        {expires_at , <<"exp">> , fun check_expiration/3}
    ].

check_presence(_, V, _) when is_binary(V) ->
    V;
check_presence(C, undefined, _) ->
    throw({invalid_token, {missing, C}}).

check_expiration(_, Exp = 0, _) ->
    Exp;
check_expiration(_, Exp, Opts) when is_integer(Exp) ->
    case get_check_expiry(Opts) of
        {true, Now} when Exp > Now ->
            Exp;
        false when Exp > 0 ->
            Exp;
        _ ->
            throw({invalid_token, expired})
    end;
check_expiration(C, undefined, _) ->
    throw({invalid_token, {missing, C}});
check_expiration(C, V, _) ->
    throw({invalid_token, {badarg, {C, V}}}).

get_check_expiry(Opts) ->
    case maps:get(check_expired_as_of, Opts, undefined) of
        Now when is_integer(Now) ->
            {true, Now};
        undefined ->
            false
    end.

-spec get_subject_id(t()) -> binary().

get_subject_id({_Id, {SubjectID, _ACL}, _Claims}) ->
    SubjectID.

-spec get_claims(t()) -> claims().

get_claims({_Id, _Subject, Claims}) ->
    Claims.

-spec get_claim(binary(), t()) -> term().

get_claim(ClaimName, {_Id, _Subject, Claims}) ->
    maps:get(ClaimName, Claims).

-spec get_claim(binary(), t(), term()) -> term().

get_claim(ClaimName, {_Id, _Subject, Claims}, Default) ->
    maps:get(ClaimName, Claims, Default).

%%

encode_roles(DomainRoles) when is_map(DomainRoles) andalso map_size(DomainRoles) > 0 ->
    F = fun(_, Roles) -> #{<<"roles">> => uac_acl:encode(Roles)} end,
    #{<<"resource_access">> => maps:map(F, DomainRoles)};
encode_roles(_) ->
    #{}.

decode_roles(Claims) ->
    Roles = case maps:get(<<"resource_access">>, Claims, undefined) of
        Resources when is_map(Resources) andalso map_size(Resources) > 0 ->
            Accepted = uac_conf:get_domain_name(),
           try_get_roles(Resources, Accepted);
        undefined ->
            undefined;
        _ ->
            % Resources is not map or an empty one
            throw({invalid_token, {invalid, acl}})
    end,
    {Roles, maps:remove(<<"resource_access">>, Claims)}.

try_get_roles(Resources, Accepted) ->
    case maps:get(Accepted, Resources, undefined) of
        #{<<"roles">> := Roles} ->
            Roles;
        undefined ->
            []
    end.

%%

insert_key(Keyname, KeyInfo = #{kid := KID}) ->
    insert_values(#{
        {keyname, Keyname} => KeyInfo,
        {kid, KID}         => KeyInfo
    }).

get_key_by_name(Keyname) ->
    lookup_value({keyname, Keyname}).

get_key_by_kid(KID) ->
    lookup_value({kid, KID}).

base64url_to_map(Base64) when is_binary(Base64) ->
    jsx:decode(base64url:decode(Base64), [return_maps]).

%%

-define(TABLE, ?MODULE).

create_table() ->
    _ = ets:new(?TABLE, [set, public, named_table, {read_concurrency, true}]),
    ok.

insert_values(Values) ->
    true = ets:insert(?TABLE, maps:to_list(Values)),
    ok.

lookup_value(Key) ->
    case ets:lookup(?TABLE, Key) of
        [{Key, Value}] ->
            Value;
        [] ->
            undefined
    end.
