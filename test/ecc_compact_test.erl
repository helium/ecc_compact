-module(ecc_compact_test).

-include_lib("public_key/include/public_key.hrl").
-include_lib("eunit/include/eunit.hrl").

generate_non_compliant_key() ->
    Key = public_key:generate_key({namedCurve,?secp256r1}),
    case ecc_compact:is_compact(Key) of
        {true, _} ->
            generate_non_compliant_key();
        false ->
            Key
    end.

ecc_noncompliant_test() ->
    Key = generate_non_compliant_key(),
    ?assertNot(ecc_compact:is_compact(Key)),
    #'ECPrivateKey'{parameters=_Params, publicKey=PubKey} = Key,
    <<4, X:32/binary, _Y:32/binary>> = PubKey,
    ?assertNotEqual({#'ECPoint'{point=PubKey}, {namedCurve, ?secp256r1}}, ecc_compact:recover(X)),
    ok.

ecc_compliant_test() ->
    {ok, Key, X} = ecc_compact:generate_compliant_key(),
    ?assertEqual({true, X}, ecc_compact:is_compact(Key)),
    #'ECPrivateKey'{parameters=_Params, publicKey=PubKey} = Key,
    <<4, X:32/binary, _Y:32/binary>> = PubKey,
    ECPubKey = {#'ECPoint'{point=PubKey}, {namedCurve, ?secp256r1}},
    ?assertEqual(ECPubKey, ecc_compact:recover(X)),
    ?assertEqual({true, X}, ecc_compact:is_compact(ECPubKey)),
    ok.

wrong_curve_test() ->
    %% generate the koblitz curve
    Key = public_key:generate_key({namedCurve,?secp256k1}),
    ?assertError(badarg, ecc_compact:is_compact(Key)),
    #'ECPrivateKey'{parameters=_Params, publicKey=PubKey} = Key,
    ECPubKey = {#'ECPoint'{point=PubKey}, {namedCurve, ?secp256r1}},
    <<4, X:32/binary, _Y:32/binary>> = PubKey,
    try ecc_compact:recover(X) of
        Result ->
            %% point happens to somehow make sense, but it should not return a sane key
            ?assertNotEqual(ECPubKey, Result)
    catch
        error:enotsup ->
            ?assert(true)
    end,
    ok.
