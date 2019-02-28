-module(uac_acl_SUITE).

-include_lib("stdlib/include/assert.hrl").
-include_lib("common_test/include/ct.hrl").

-export([all/0]).
-export([init_per_suite/1]).
-export([end_per_suite/1]).
-export([init_per_group/2]).
-export([end_per_group/2]).
-export([init_per_testcase/2]).
-export([end_per_testcase/2]).

-export([
    illegal_input_test/1,
    empty_test/1,
    stable_encoding_test/1,
    remove_scopes_test/1,
    redundancy_test/1,
    match_scope_test/1
]).

-spec illegal_input_test(config())   -> _.
-spec empty_test(config())           -> _.
-spec stable_encoding_test(config()) -> _.
-spec remove_scopes_test(config())   -> _.
-spec redundancy_test(config())      -> _.
-spec match_scope_test(config())     -> _.

-type test_case_name()  :: atom().
-type config()          :: [{atom(), any()}].
-type group_name()      :: atom().

-spec all() ->
    [test_case_name()].
all() ->
    [
        illegal_input_test,
        empty_test,
        stable_encoding_test,
        remove_scopes_test,
        redundancy_test,
        match_scope_test
    ].

-spec init_per_suite(config()) ->
    config().
init_per_suite(Config) ->
    Apps = genlib_app:start_application(uac),
    uac:configure(#{
        jwt => #{
            keyset => #{
                test => {pem_file, get_keysource("keys/local/private.pem", Config)}
            }
        },
        access => #{
            service_name => <<"test">>,
            resource_hierarchy => #{
                party               => #{invoice_templates => #{invoice_template_invoices => #{}}},
                customers           => #{bindings => #{}},
                invoices            => #{payments => #{}},
                payment_resources => #{}
            }
        }
    }),
    [{apps, Apps}] ++ Config.

-spec init_per_group(group_name(), config()) ->
    config().
init_per_group(_Name, Config) ->
    Config.

-spec init_per_testcase(group_name(), config()) ->
    config().
init_per_testcase(_Name, Config) ->
    Config.

-spec end_per_suite(config()) ->
    config().
end_per_suite(Config) ->
    Config.

-spec end_per_group(group_name(), config()) ->
    config().
end_per_group(_Name, Config) ->
    Config.

-spec end_per_testcase(test_case_name(), config()) ->
    config().
end_per_testcase(_Name, Config) ->
    Config.


illegal_input_test(_C) ->
    ?assertError({badarg, {scope     , _}}, from_list([{[], read}])),
    ?assertError({badarg, {permission, _}}, from_list([{[invoices], wread}])),
    ?assertError({badarg, {resource  , _}}, from_list([{[payments], read}])).

empty_test(_C) ->
    [] = encode(from_list([])),
    [] = to_list(decode([])).

stable_encoding_test(_C) ->
    ACL1 = from_list([
        {[party], read},
        {[party], write},
        {[invoices], read},
        {[invoices, payments], read},
        {[{invoices, <<"42">>}, payments], write}
    ]),
    Enc1 = [
        <<"invoices.42.payments:write">>,
        <<"invoices.*.payments:read">>,
        <<"party:read">>,
        <<"party:write">>,
        <<"invoices:read">>
    ],
    Enc1 = encode(ACL1),
    ACL1 = decode(Enc1),
    ACL1 = decode(encode(ACL1)).

redundancy_test(_C) ->
    [<<"party:read">>] = encode(from_list([{[party], read}, {[party], read}])).

remove_scopes_test(_C) ->
    ?assertEqual(new(), remove([party], read, new())),
    ?assertEqual(
        from_list([{[party], write}]),
        remove([invoices], read, from_list([{[party], write}, {[invoices], read}]))
    ),
    ?assertEqual(
        new(),
        remove([party], read,
            remove([party], write,
                remove([party], read,
                    from_list([{[party], read}, {[party], write}])
                )
            )
        )
    ).

match_scope_test(_C) ->
    ACL = from_list([
        {[party], read},
        {[party], write},
        {[invoices], read},
        {[invoices, payments], write},
        {[{invoices, <<"42">>}], write},
        {[{invoices, <<"42">>}, payments], read}
    ]),
    ?assertError({badarg, _}   , match([], ACL)),
    ?assertEqual([write]       , match([{invoices, <<"42">>}], ACL)),
    ?assertEqual([read]        , match([{invoices, <<"43">>}], ACL)),
    ?assertEqual([read]        , match([{invoices, <<"42">>}, {payments, <<"1">>}], ACL)),
    ?assertEqual([write]       , match([{invoices, <<"43">>}, {payments, <<"1">>}], ACL)),
    ?assertEqual([read, write] , match([{party, <<"BLARGH">>}], ACL)),
    ?assertEqual([]            , match([payment_resources], ACL)).

new() ->
    uac_acl:new().

from_list(L) ->
    uac_acl:from_list(L).

to_list(L) ->
    uac_acl:to_list(L).

remove(S, P, ACL) ->
    uac_acl:remove_scope(S, P, ACL).

match(S, ACL) ->
    uac_acl:match(S, ACL).

encode(ACL) ->
    uac_acl:encode(ACL).

decode(Bin) ->
    uac_acl:decode(Bin).

get_keysource(Key, Config) ->
    filename:join(?config(data_dir, Config), Key).
