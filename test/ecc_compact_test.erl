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

key_with_leading_zeros_in_y_coordinate_test() ->
    Key = {'ECPrivateKey',1,
           <<24,166,124,60,235,151,150,175,21,14,17,166,20,155,69,168,147,56,
             174,143,138,64,60,78,4,101,129,96,135,46,205,204>>,
           {namedCurve,{1,2,840,10045,3,1,7}},
           <<4,216,67,1,187,4,120,72,243,120,252,76,68,11,155,208,244,56,
             101,253,67,214,128,225,88,64,204,147,185,108,176,237,19,0,109,
             55,36,142,111,190,1,48,190,235,92,27,234,62,176,156,121,37,71,
             202,191,139,227,53,139,188,53,37,254,84,33>>},
    #'ECPrivateKey'{parameters=_Params, publicKey=PubKey} = Key,
    ECPubKey = {#'ECPoint'{point=PubKey}, {namedCurve, ?secp256r1}},
    <<4, X:32/binary, _Y:32/binary>> = PubKey,
    ?assertEqual(ECPubKey, ecc_compact:recover(X)).
