-module(uac).

%% App

-behaviour(application).

-export([start/2, stop/1]).

%% Supervisor

-behaviour(supervisor).

-export([init/1]).

%%API

-export([configure/1]).
-export([authorize_api_key/2]).
-export([authorize_operation/2]).
-export([authorize_operation/3]).

-type context() :: uac_authorizer_jwt:t().
-type context(T) :: uac_authorizer_jwt:t(T).
-type claims() :: uac_authorizer_jwt:claims().

-type configuration(T) :: #{
    jwt := uac_authorizer_jwt:options(T),
    access := uac_conf:options()
}.

-type configuration() :: configuration(any()).

-type verification_opts() :: #{
    check_expired_as_of => genlib_time:ts()
}.

-type api_key() :: binary().
-type key_type() :: bearer.
-type domain_name() :: uac_authorizer_jwt:domain_name().

-export_type([context/0]).
-export_type([context/1]).
-export_type([configuration/0]).
-export_type([configuration/1]).
-export_type([claims/0]).
-export_type([verification_opts/0]).

%%
% API
%%

-spec configure(configuration()) -> ok.
configure(Config) ->
    AuthorizerConfig = maps:get(jwt, Config),
    AccessConfig = maps:get(access, Config),
    ok = uac_authorizer_jwt:configure(AuthorizerConfig),
    ok = uac_conf:configure(AccessConfig).

-spec authorize_api_key(api_key(), verification_opts()) -> {ok, context()} | {error, Reason :: atom()}.
authorize_api_key(ApiKey, VerificationOpts) ->
    case parse_api_key(ApiKey) of
        {ok, {Type, Credentials}} ->
            authorize_api_key(Type, Credentials, VerificationOpts);
        {error, Error} ->
            {error, Error}
    end.

-spec parse_api_key(ApiKey :: api_key()) -> {ok, {bearer, uac_authorizer_jwt:token()}} | {error, Reason :: atom()}.
parse_api_key(ApiKey) ->
    case ApiKey of
        <<"Bearer ", Token/binary>> ->
            {ok, {bearer, Token}};
        _ ->
            {error, unsupported_auth_scheme}
    end.

-spec authorize_api_key(key_type(), uac_authorizer_jwt:token(), verification_opts()) ->
    {ok, context()} | {error, Reason :: atom()}.
authorize_api_key(bearer, Token, VerificationOpts) ->
    uac_authorizer_jwt:verify(Token, VerificationOpts).

%%

-spec authorize_operation(uac_conf:operation_access_scopes(), context()) ->
    ok | {error, unauthorized} | {error, {acl, _Reason}}.
authorize_operation(AccessScope, Context) ->
    authorize_operation(AccessScope, Context, uac_conf:get_domain_name()).

-spec authorize_operation(uac_conf:operation_access_scopes(), context(), domain_name()) ->
    ok | {error, unauthorized} | {error, {acl, _Reason}}.
authorize_operation(AccessScope, Context, Domain) ->
    case uac_authorizer_jwt:get_acl(Domain, Context) of
        {ok, ACL} ->
            authorize_operation_(AccessScope, ACL);
        {error, Reason} ->
            {error, {acl, Reason}}
    end.

authorize_operation_(AccessScope, ACL) ->
    case
        lists:all(
            fun({Scope, Permission}) ->
                lists:member(Permission, uac_acl:match(Scope, ACL))
            end,
            AccessScope
        )
    of
        true ->
            ok;
        false ->
            {error, unauthorized}
    end.

%%
% App
%%

-spec start(any(), any()) -> {ok, pid()} | {error, Reason :: term()}.
start(_StartType, _StartArgs) ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

-spec stop(any()) -> ok.
stop(_State) ->
    ok.

%%
% Supervisor
%%

-spec init([]) -> {ok, {supervisor:sup_flags(), [supervisor:child_spec()]}}.
init([]) ->
    AuthorizerSpec = uac_authorizer_jwt:get_child_spec(),
    AccessSpec = uac_conf:get_child_spec(),
    SupFlags = #{},
    Children = AuthorizerSpec ++ AccessSpec,
    {ok, {SupFlags, Children}}.
