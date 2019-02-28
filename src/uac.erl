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

-type context() :: uac_authorizer_jwt:t().
-type claims()  :: uac_authorizer_jwt:claims().

-type configuration() :: #{
    jwt := uac_authorizer_jwt:options(),
    access := uac_conf:options()
}.

-type verification_opts() :: #{
    check_expired_as_of => genlib_time:ts()
}.

-type api_key()      :: binary().

-export_type([context/0]).
-export_type([claims/0]).
-export_type([verification_opts/0]).

%%
% API
%%

-spec configure(configuration()) ->
    ok.
configure(Config) ->
    AuthorizerConfig = maps:get(jwt, Config),
    AccessConfig = maps:get(access, Config),
    ok = uac_authorizer_jwt:configure(AuthorizerConfig),
    ok = uac_conf:configure(AccessConfig).

-spec authorize_api_key(
    ApiKey      :: api_key(),
    VerificationOpts :: verification_opts()
) -> {ok, Context :: context()} | {error, Reason :: atom()}.

authorize_api_key(ApiKey, VerificationOpts) ->
    case parse_api_key(ApiKey) of
        {ok, {Type, Credentials}} ->
            authorize_api_key(Type, Credentials, VerificationOpts);
        {error, Error} ->
            {error, Error}
    end.

-spec parse_api_key(ApiKey :: api_key()) ->
    {ok, {bearer, Credentials :: binary()}} | {error, Reason :: atom()}.

parse_api_key(ApiKey) ->
    case ApiKey of
        <<"Bearer ", Credentials/binary>> ->
            {ok, {bearer, Credentials}};
        _ ->
            {error, unsupported_auth_scheme}
    end.

-spec authorize_api_key(
    Type :: atom(),
    Credentials :: binary(),
    VerificationOpts :: verification_opts()
) ->
    {ok, Context :: context()} | {error, Reason :: atom()}.

authorize_api_key(bearer, Token, VerificationOpts) ->
    uac_authorizer_jwt:verify(Token, VerificationOpts).

%%

-spec authorize_operation(
    AccessScope :: uac_conf:operation_access_scopes(),
    Auth :: uac_authorizer_jwt:t()
) ->
    ok | {error, unauthorized}.

authorize_operation(AccessScope, {_, {_SubjectID, ACL}, _}) ->
    case lists:all(
        fun ({Scope, Permission}) ->
            lists:member(Permission, uac_acl:match(Scope, ACL))
        end,
        AccessScope
    ) of
        true ->
            ok;
        false ->
            {error, unauthorized}
    end.

%%
% App
%%

-spec start(any(), any()) ->
    {ok, pid()} | {error, Reason :: term()}.
start(_StartType, _StartArgs) ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

-spec stop(any()) ->
    ok.
stop(_State) ->
    ok.

%%
% Supervisor
%%

-spec init([]) ->
    {ok, {supervisor:sup_flags(), [supervisor:child_spec()]}}.
init([]) ->
    AuthorizerSpec = uac_authorizer_jwt:get_child_spec(),
    AccessSpec = uac_conf:get_child_spec(),
    SupFlags = #{},
    Children = AuthorizerSpec ++ AccessSpec,
    {ok, {SupFlags, Children}}.
