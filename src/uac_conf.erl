-module(uac_conf).

%%

-export([get_child_spec/0]).
-export([init/1]).

%% API

-export([configure/1]).
-export([get_service_name/0]).
-export([get_resource_hierarchy/0]).

-type operation_access_scopes() :: [{uac_acl:scope(), uac_acl:permission()}].
-type service_name() :: binary().
-type resource_hierarchy() :: #{uac_acl:resource() => resource_hierarchy() | #{}}.

-type options() :: #{
    service_name := service_name(),
    resource_hierarchy := resource_hierarchy()
}.
-export_type([options/0]).
-export_type([operation_access_scopes/0]).

%%

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
%% API
%%

-spec get_service_name() ->
    service_name().
get_service_name() ->
    lookup_value(service_name).

-spec get_resource_hierarchy() ->
    resource_hierarchy().
get_resource_hierarchy() ->
    lookup_value(resource_hierarchy).

%%

-spec configure(options()) ->
    ok.
configure(Config) ->
    ok = insert_values(Config).

%%

-define(TABLE, ?MODULE).

create_table() ->
    _ = ets:new(?TABLE, [set, public, named_table, {read_concurrency, true}]),
    ok.

insert_values(Values) ->
    true = ets:insert(?TABLE, maps:to_list(Values)),
    ok.

lookup_value(Key) ->
    lookup_value(Key, undefined).

lookup_value(Key, Default) ->
    case ets:lookup(?TABLE, Key) of
        [{Key, Value}] ->
            Value;
        [] ->
            Default
    end.
