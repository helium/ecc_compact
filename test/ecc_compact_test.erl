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

% K256 key with an odd Y-coordinate
odd_y_secp256k1_key() ->
    {'ECPrivateKey',1,
        <<86,224,37,238,147,228,215,15,7,69,238,15,215,101,118,204,88,
          192,237,159,209,202,212,206,200,158,30,189,122,140,138,78>>,
        {namedCurve,{1,3,132,0,10}},
        <<4,198,148,223,114,141,97,92,50,2,119,52,132,135,74,86,152,
          86,151,212,196,29,141,240,191,206,136,179,113,154,21,246,
          140,47,252,2,53,108,192,138,6,133,162,195,4,177,125,160,200,
          22,102,188,89,214,120,43,115,16,60,225,91,230,34,88,185>>}.

% K256 key with an even Y-coordinate
even_y_secp256k1_key() ->
    {'ECPrivateKey',1,
        <<145,173,109,108,218,212,158,120,195,149,91,120,205,147,243,
          54,205,33,110,24,29,239,100,119,220,149,4,44,150,167,200,203>>,
        {namedCurve,{1,3,132,0,10}},
        <<4,96,208,77,104,198,60,254,164,98,63,137,248,175,65,151,142,
          67,192,223,39,122,40,162,139,152,82,181,33,130,160,232,206,
          210,81,255,21,59,227,197,245,116,226,146,87,254,223,114,215,
          77,82,108,166,10,22,186,72,85,119,155,25,100,141,231,228>>}.

ecc_noncompliant_test() ->
    Key = generate_non_compliant_key(),
    ?assertNot(ecc_compact:is_compact(Key)),
    #'ECPrivateKey'{parameters=_Params, publicKey=PubKey} = Key,
    <<4, X:32/binary, _Y:32/binary>> = PubKey,
    ?assertNotEqual({#'ECPoint'{point=PubKey}, {namedCurve, ?secp256r1}}, ecc_compact:recover_compact_key(X)),
    ok.

ecc_compliant_test() ->
    {ok, Key, X} = ecc_compact:generate_key(),
    ?assertEqual({true, X}, ecc_compact:is_compact(Key)),
    #'ECPrivateKey'{parameters=_Params, publicKey=PubKey} = Key,
    <<4, X:32/binary, _Y:32/binary>> = PubKey,
    ECPubKey = {#'ECPoint'{point=PubKey}, {namedCurve, ?secp256r1}},
    ?assertEqual(ECPubKey, ecc_compact:recover_compact_key(X)),
    ?assertEqual({true, X}, ecc_compact:is_compact(ECPubKey)),
    ok.

wrong_curve_test() ->
    %% generate the koblitz curve
    Key = public_key:generate_key({namedCurve,?secp256k1}),
    ?assertError(badarg, ecc_compact:is_compact(Key)),
    #'ECPrivateKey'{parameters=_Params, publicKey=PubKey} = Key,
    ECPubKey = {#'ECPoint'{point=PubKey}, {namedCurve, ?secp256r1}},
    <<4, X:32/binary, _Y:32/binary>> = PubKey,
    try ecc_compact:recover_compact_key(X) of
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
    ?assertEqual(ECPubKey, ecc_compact:recover_compact_key(X)).

roundtrip_k256_odd_y_test() ->
    Key = odd_y_secp256k1_key(),
    #'ECPrivateKey'{parameters=_Params, publicKey=PubKey} = Key,
    ECPubKey = {#'ECPoint'{point=PubKey}, {namedCurve, ?secp256k1}},
    <<4, X:32/binary, Y:256>> = PubKey,
    % Y should be odd
    ?assertEqual(Y rem 2, 1),
    CompressedKey = <<3, X/binary>>,
    UncompressedPubKey = ecc_compact:recover_compressed_key(CompressedKey),
    ?assertEqual(UncompressedPubKey, ECPubKey).

roundtrip_k256_even_y_test() ->
    Key = even_y_secp256k1_key(),
    #'ECPrivateKey'{parameters=_Params, publicKey=PubKey} = Key,
    ECPubKey = {#'ECPoint'{point=PubKey}, {namedCurve, ?secp256k1}},
    <<4, X:32/binary, Y:256>> = PubKey,
    % Y should be even
    ?assertEqual(Y rem 2, 0),
    CompressedKey = <<2, X/binary>>,
    UncompressedPubKey = ecc_compact:recover_compressed_key(CompressedKey),
    ?assertEqual(UncompressedPubKey, ECPubKey).
