-module(uac_authorizer_jwt).

%%
-export([init/1]).
-export([get_child_spec/0]).

% TODO
% Extend interface to support proper keystore manipulation

-export([configure/1]).
-export([issue/4]).
-export([verify/2]).

%%

-export([get_token_id/1]).
-export([get_subject_email/1]).
-export([set_subject_email/2]).
-export([get_expires_at/1]).

-export([get_subject_id/1]).
-export([get_claims/1]).
-export([get_claim/2]).
-export([get_claim/3]).
-export([create_claims/3]).

%%

-include_lib("jose/include/jose_jwk.hrl").
-include_lib("jose/include/jose_jwt.hrl").

-type keyname() :: term().
-type kid() :: binary().
-type key() :: #jose_jwk{}.
-type token() :: binary().
-type claim() :: domains() | expiration() | term().
-type claims() :: #{binary() => claim()}.
-type subject_id() :: binary().
-type t(T) :: {id(), subject_id(), claims(), metadata(T)}.
-type t() :: t(any()).
-type domain_name() :: binary().
-type domains() :: #{domain_name() => uac_acl:t()}.
-type expiration() :: unlimited | integer().

-type id() :: binary().

-type metadata(T) :: T.
-type metadata() :: metadata(any()).

-export_type([t/0]).
-export_type([t/1]).
-export_type([claims/0]).
-export_type([token/0]).
-export_type([expiration/0]).
-export_type([domain_name/0]).
-export_type([domains/0]).
-export_type([metadata/0]).
-export_type([metadata/1]).

-define(CLAIM_TOKEN_ID, <<"jti">>).
-define(CLAIM_SUBJECT_ID, <<"sub">>).
-define(CLAIM_SUBJECT_EMAIL, <<"email">>).
-define(CLAIM_EXPIRES_AT, <<"exp">>).
-define(CLAIM_ACCESS, <<"resource_access">>).

%%

-type options(T) :: #{
    %% The set of keys used to sign issued tokens and verify signatures on such
    %% tokens.
    keyset => keyset(T)
}.

-type options() :: options(any()).

-export_type([options/0]).
-export_type([options/1]).

-type keyset(T) :: #{
    keyname() => key_opts(T)
}.

-type key_opts(T) :: #{
    source := keysource(),
    metadata => metadata(T)
}.

-type keysource() ::
    {pem_file, file:filename()}.

-spec get_child_spec() -> [supervisor:child_spec()].
get_child_spec() ->
    [
        #{
            id => ?MODULE,
            start => {supervisor, start_link, [?MODULE, []]},
            type => supervisor
        }
    ].

-spec init([]) -> {ok, {supervisor:sup_flags(), [supervisor:child_spec()]}}.
init([]) ->
    ok = create_table(),
    {ok, {#{}, []}}.

%%

-spec configure(options()) -> ok.
configure(Options) ->
    Keyset = parse_options(Options),
    _ = maps:map(fun ensure_store_key/2, Keyset),
    ok.

parse_options(Options) ->
    Keyset = maps:get(keyset, Options, #{}),
    _ = is_map(Keyset) orelse exit({invalid_option, keyset, Keyset}),
    _ = genlib_map:foreach(
        fun(KeyName, #{source := Source}) ->
            _ =
                is_keysource(Source) orelse
                    exit({invalid_source, KeyName, Source})
        end,
        Keyset
    ),
    Keyset.

is_keysource({pem_file, Fn}) ->
    is_list(Fn) orelse is_binary(Fn);
is_keysource(_) ->
    false.

ensure_store_key(Keyname, KeyOpts) ->
    Source = maps:get(source, KeyOpts),
    Metadata = maps:get(metadata, KeyOpts, #{}),
    case store_key(Keyname, Source, Metadata) of
        ok ->
            ok;
        {error, Reason} ->
            exit({import_error, Keyname, Source, Reason})
    end.

%%

-spec store_key(keyname(), {pem_file, file:filename()}, metadata()) -> ok | {error, file:posix() | {unknown_key, _}}.
store_key(Keyname, {pem_file, Filename}, Metadata) ->
    store_key(Keyname, {pem_file, Filename}, Metadata, #{
        kid => fun derive_kid_from_public_key_pem_entry/1
    }).

derive_kid_from_public_key_pem_entry(JWK) ->
    JWKPublic = jose_jwk:to_public(JWK),
    {_Module, PublicKey} = JWKPublic#jose_jwk.kty,
    {_PemEntry, Data, _} = public_key:pem_entry_encode('SubjectPublicKeyInfo', PublicKey),
    jose_base64url:encode(crypto:hash(sha256, Data)).

-type store_opts() :: #{
    kid => fun((key()) -> kid())
}.

-spec store_key(keyname(), {pem_file, file:filename()}, metadata(), store_opts()) ->
    ok | {error, file:posix() | {unknown_key, _}}.
store_key(Keyname, {pem_file, Filename}, Metadata, Opts) ->
    case jose_jwk:from_pem_file(Filename) of
        JWK = #jose_jwk{} ->
            Key = construct_key(derive_kid(JWK, Opts), JWK),
            ok = insert_key(Keyname, Key#{metadata => Metadata});
        Error = {error, _} ->
            Error
    end.

derive_kid(JWK, #{kid := DeriveFun}) when is_function(DeriveFun, 1) ->
    DeriveFun(JWK).

construct_key(KID, JWK) ->
    Signer =
        try
            jose_jwk:signer(JWK)
        catch
            error:_ -> undefined
        end,
    Verifier =
        try
            jose_jwk:verifier(JWK)
        catch
            error:_ -> undefined
        end,
    #{
        jwk => JWK,
        kid => KID,
        signer => Signer,
        can_sign => Signer /= undefined,
        verifier => Verifier,
        can_verify => Verifier /= undefined
    }.

%%

-spec issue(id(), subject_id(), claims(), keyname()) ->
    {ok, token()}
    | {error, nonexistent_key}
    | {error, {invalid_signee, Reason :: atom()}}.
issue(JTI, SubjectID, Claims, Signee) ->
    case try_get_key_for_sign(Signee) of
        {ok, Key} ->
            FinalClaims = construct_final_claims(SubjectID, Claims, JTI),
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

construct_final_claims(SubjectID, Claims, JTI) ->
    Token0 = #{?CLAIM_TOKEN_ID => JTI, ?CLAIM_SUBJECT_ID => SubjectID},
    EncodedClaims = maps:map(fun encode_claim/2, Claims),
    maps:merge(EncodedClaims, Token0).

encode_claim(?CLAIM_EXPIRES_AT, Expiration) ->
    mk_expires_at(Expiration);
encode_claim(?CLAIM_ACCESS, DomainRoles) ->
    encode_roles(DomainRoles);
encode_claim(_, Value) ->
    Value.

mk_expires_at(unlimited) ->
    0;
mk_expires_at(Dl) ->
    Dl.

sign(#{kid := KID, jwk := JWK, signer := #{} = JWS}, Claims) ->
    JWT = jose_jwt:sign(JWK, JWS#{<<"kid">> => KID}, Claims),
    {_Modules, Token} = jose_jws:compact(JWT),
    {ok, Token}.

%%

-spec verify(token(), uac:verification_opts()) ->
    {ok, t()}
    | {error,
        {invalid_token,
            badarg
            | {badarg, term()}
            | {missing, atom()}
            | expired
            | {malformed_acl, term()}}
        | {nonexistent_key, kid()}
        | {invalid_operation, term()}
        | invalid_signature}.
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
        #{jwk := JWK, verifier := Algs, metadata := Metadata} ->
            _ = lists:member(Alg, Algs) orelse throw({invalid_operation, Alg}),
            verify_with_key(JWK, ExpandedToken, VerificationOpts, Metadata);
        undefined ->
            {error, {nonexistent_key, KID}}
    end.

verify_with_key(JWK, ExpandedToken, VerificationOpts, Metadata) ->
    case jose_jwt:verify(JWK, ExpandedToken) of
        {true, #jose_jwt{fields = Claims}, _JWS} ->
            _ = validate_claims(Claims, VerificationOpts),
            get_result(Claims, VerificationOpts, Metadata);
        {false, _JWT, _JWS} ->
            {error, invalid_signature}
    end.

validate_claims(Claims, VerificationOpts) ->
    validate_claims(Claims, get_validators(), VerificationOpts).

validate_claims(Claims, [{Name, Claim, Validator} | Rest], VerificationOpts) ->
    _ = Validator(Name, maps:get(Claim, Claims, undefined), VerificationOpts),
    validate_claims(Claims, Rest, VerificationOpts);
validate_claims(Claims, [], _) ->
    Claims.

get_result(Claims, VerificationOpts, Metadata) ->
    try
        #{
            ?CLAIM_TOKEN_ID := TokenID,
            ?CLAIM_SUBJECT_ID := SubjectID
        } = Claims,
        {ok, {TokenID, SubjectID, decode_roles(Claims, VerificationOpts), Metadata}}
    catch
        error:{badarg, _} = Reason ->
            throw({invalid_token, {malformed_acl, Reason}})
    end.

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
        {token_id, ?CLAIM_TOKEN_ID, fun check_presence/3},
        {subject_id, ?CLAIM_SUBJECT_ID, fun check_presence/3},
        {expires_at, ?CLAIM_EXPIRES_AT, fun check_expiration/3}
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
check_expiration(C, undefined, Opts) ->
    case get_check_expiry(Opts) of
        {true, _} -> throw({invalid_token, {missing, C}});
        false -> undefined
    end;
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
get_subject_id({_Id, SubjectID, _Claims, _Metadata}) ->
    SubjectID.

-spec get_token_id(t()) -> binary().
get_token_id({Id, _SubjectID, _Claims, _Metadata}) ->
    Id.

-spec get_claims(t()) -> claims().
get_claims({_Id, _Subject, Claims, _Metadata}) ->
    Claims.

-spec get_claim(binary(), t()) -> term().
get_claim(ClaimName, {_Id, _Subject, Claims, _Metadata}) ->
    maps:get(ClaimName, Claims).

-spec get_claim(binary(), t(), term()) -> term().
get_claim(ClaimName, {_Id, _Subject, Claims, _Metadata}, Default) ->
    maps:get(ClaimName, Claims, Default).

-spec create_claims(claims(), expiration(), domains()) -> claims().
create_claims(Claims, Expiration, DomainRoles) ->
    Claims#{
        ?CLAIM_EXPIRES_AT => Expiration,
        ?CLAIM_ACCESS => DomainRoles
    }.

-spec get_expires_at(t()) -> expiration().
get_expires_at({_Id, _Subject, Claims, _Metadata}) ->
    case maps:get(?CLAIM_EXPIRES_AT, Claims) of
        0 -> unlimited;
        V -> V
    end.

-spec get_subject_email(t()) -> binary() | undefined.
get_subject_email(T) ->
    get_claim(?CLAIM_SUBJECT_EMAIL, T, undefined).

-spec set_subject_email(binary(), claims()) -> claims().
set_subject_email(SubjectID, Claims) ->
    false = maps:is_key(?CLAIM_SUBJECT_EMAIL, Claims),
    Claims#{?CLAIM_SUBJECT_EMAIL => SubjectID}.

%%

encode_roles(DomainRoles) when is_map(DomainRoles) andalso map_size(DomainRoles) > 0 ->
    F = fun(_, Roles) -> #{<<"roles">> => uac_acl:encode(Roles)} end,
    maps:map(F, DomainRoles);
encode_roles(_) ->
    #{}.

decode_roles(Claims, VerificationOpts) ->
    case genlib_map:get(?CLAIM_ACCESS, Claims) of
        undefined ->
            Claims;
        ResourceAcceess when is_map(ResourceAcceess) ->
            % @FIXME This is a temporary solution
            % rework interface the way this line won't be needed
            Domains = maps:get(domains_to_decode, VerificationOpts, maps:keys(ResourceAcceess)),
            DomainRoles = maps:map(
                fun(_, #{<<"roles">> := Roles}) -> uac_acl:decode(Roles) end,
                maps:with(Domains, ResourceAcceess)
            ),
            Claims#{?CLAIM_ACCESS => DomainRoles};
        _ ->
            throw({invalid_token, {invalid, acl}})
    end.

%%

insert_key(Keyname, KeyInfo = #{kid := KID}) ->
    insert_values(#{
        {keyname, Keyname} => KeyInfo,
        {kid, KID} => KeyInfo
    }).

get_key_by_name(Keyname) ->
    lookup_value({keyname, Keyname}).

get_key_by_kid(KID) ->
    lookup_value({kid, KID}).

base64url_to_map(Base64) when is_binary(Base64) ->
    {ok, Json} = jose_base64url:decode(Base64),
    jsx:decode(Json, [return_maps]).

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
