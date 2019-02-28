-module(uac_tests_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("jose/include/jose_jwk.hrl").

-export([all/0]).
-export([groups/0]).
-export([init_per_suite/1]).
-export([end_per_suite/1]).
-export([init_per_group/2]).
-export([end_per_group/2]).
-export([init_per_testcase/2]).
-export([end_per_testcase/2]).

-export([
    successful_auth_test/1,
    invalid_permissions_test/1,
    bad_token_test/1,
    no_token_test/1,

    force_expiration_test/1,
    force_expiration_fail_test/1,

    bad_signee_test/1,

    different_issuers_test/1
]).

-type test_case_name()  :: atom().
-type config()          :: [{atom(), any()}].
-type group_name()      :: atom().

-define(expire_as_of_now, #{
    check_expired_as_of => genlib_time:unow()
}).

-define(test_service_acl(Access), [{[test_resource], Access}]).

-spec all() ->
    [test_case_name()].
all() ->
    [
        {group, general_tests},
        {group, different_issuers}
    ].

-spec groups() ->
    [{group_name(), list(), [test_case_name()]}].
groups() ->
    [
        {general_tests, [],
            [
                successful_auth_test,
                invalid_permissions_test,
                bad_token_test,
                no_token_test,
                force_expiration_test,
                force_expiration_fail_test,
                bad_signee_test
            ]
        },
        {different_issuers, [],
            [
                different_issuers_test
            ]
        }
    ].

-spec init_per_suite(config()) ->
    config().
init_per_suite(Config) ->
    Config.

-spec init_per_group(group_name(), config()) ->
    config().
init_per_group(general_tests, Config) ->
    Apps = [
        genlib_app:start_application(snowflake),
        genlib_app:start_application(uac)
    ],
    uac:configure(#{
        jwt => #{
            keyset => #{
                test => {pem_file, get_keysource("keys/local/private.pem", Config)}
            }
        },
        access => #{
            service_name => <<"test">>,
            resource_hierarchy => #{
                test_resource => #{}
            }
        }
    }),
    [{apps, Apps}] ++ Config;
init_per_group(different_issuers, Config) ->
    Apps = [
        genlib_app:start_application(snowflake),
        genlib_app:start_application(uac)
    ],
    uac:configure(#{
        jwt => #{
            keyset => #{
                test => {pem_file, get_keysource("keys/local/private.pem", Config)}
            }
        },
        access => #{
            service_name => <<"test">>,
            resource_hierarchy => #{
                test_resource => #{}
            }
        }
    }),
    [{apps, Apps}] ++ Config.

-spec init_per_testcase(test_case_name(), config()) ->
    config().
init_per_testcase(_Name, Config) ->
    Config.

-spec end_per_suite(config()) ->
    _.
end_per_suite(Config) ->
    Config.

-spec end_per_group(group_name(), config()) ->
    _.
end_per_group(_Name, Config) ->
    [application:stop(App) || App <- ?config(apps, Config)].

-spec end_per_testcase(test_case_name(), config()) ->
    _.
end_per_testcase(_Name, Config) ->
    Config.

%%

-spec successful_auth_test(config()) ->
    _.
successful_auth_test(_) ->
    {ok, Token} = issue_token(?test_service_acl(write), unlimited),
    {ok, AccessContext} = uac:authorize_api_key(<<"Bearer ", Token/binary>>, #{}),
    ok = uac:authorize_operation(?test_service_acl(write), AccessContext).

-spec invalid_permissions_test(config()) ->
    _.
invalid_permissions_test(_) ->
    {ok, Token} = issue_token(?test_service_acl(read), unlimited),
    {ok, AccessContext} = uac:authorize_api_key(<<"Bearer ", Token/binary>>, #{}),
    {error, _} = uac:authorize_operation(?test_service_acl(write), AccessContext).

-spec bad_token_test(config()) ->
    _.
bad_token_test(Config) ->
    {ok, Token} = issue_dummy_token(?test_service_acl(write), Config),
    {error, _} = uac:authorize_api_key(<<"Bearer ", Token/binary>>, #{}).

-spec no_token_test(config()) ->
    _.
no_token_test(_) ->
    Token = <<"">>,
    {error, _} = uac:authorize_api_key(<<"Bearer ", Token/binary>>, #{}).

-spec force_expiration_test(config()) ->
    _.
force_expiration_test(_) ->
    {ok, Token} = issue_token(?test_service_acl(write), {deadline, 1}),
    {ok, AccessContext} = uac:authorize_api_key(<<"Bearer ", Token/binary>>, #{}),
    ok = uac:authorize_operation(?test_service_acl(write), AccessContext).

-spec force_expiration_fail_test(config()) ->
    _.
force_expiration_fail_test(_) ->
    {ok, Token} = issue_token(?test_service_acl(write), {deadline, 1}),
    {error, _} = uac:authorize_api_key(<<"Bearer ", Token/binary>>, ?expire_as_of_now).

-spec bad_signee_test(config()) ->
    _.
bad_signee_test(_) ->
    ACL = ?test_service_acl(write),
    {error, nonexistent_key} =
        uac_authorizer_jwt:issue(unique_id(), unlimited, {{<<"TEST">>, uac_acl:from_list(ACL)}, #{}}, random).

%%

-spec different_issuers_test(config()) ->
    _.
different_issuers_test(_) ->
    {ok, Token} = issue_token(?test_service_acl(write), unlimited),
    uac:configure(#{
        jwt => #{},
        access => #{
            service_name => <<"SOME_OTHER_SERVICE">>,
            resource_hierarchy => #{
                test_resource => #{}
            }
        }
    }),
    {ok, {_, {_, []}, _}} = uac:authorize_api_key(<<"Bearer ", Token/binary>>, #{}).

%%

issue_token(ACL, LifeTime) ->
    PartyID = <<"TEST">>,
    Claims = #{<<"TEST">> => <<"TEST">>},
    uac_authorizer_jwt:issue(unique_id(), LifeTime, {{PartyID, uac_acl:from_list(ACL)}, Claims}, test).

issue_dummy_token(ACL, Config) ->
    Claims = #{
        <<"jti">> => unique_id(),
        <<"sub">> => <<"TEST">>,
        <<"exp">> => 0,
        <<"resource_access">> => #{
            <<"common-api">> => #{
                <<"roles">> => uac_acl:encode(uac_acl:from_list(ACL))
            }
        }
    },
    BadPemFile = get_keysource("keys/local/dummy.pem", Config),
    BadJWK = jose_jwk:from_pem_file(BadPemFile),
    GoodPemFile = get_keysource("keys/local/private.pem", Config),
    GoodJWK = jose_jwk:from_pem_file(GoodPemFile),
    JWKPublic = jose_jwk:to_public(GoodJWK),
    {_Module, PublicKey} = JWKPublic#jose_jwk.kty,
    {_PemEntry, Data, _} = public_key:pem_entry_encode('SubjectPublicKeyInfo', PublicKey),
    KID = base64url:encode(crypto:hash(sha256, Data)),
    JWT = jose_jwt:sign(BadJWK, #{<<"alg">> => <<"RS256">>, <<"kid">> => KID}, Claims),
    {_Modules, Token} = jose_jws:compact(JWT),
    {ok, Token}.

get_keysource(Key, Config) ->
    filename:join(?config(data_dir, Config), Key).

unique_id() ->
    <<ID:64>> = snowflake:new(),
    genlib_format:format_int_base(ID, 62).
