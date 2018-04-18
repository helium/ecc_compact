%% @doc Utility module for checking whether NIST P-256 (secp256r1) ECC keys can
%% be compressed to only their X coordinate. This implementation implements the
%% strategy described in
%% [https://tools.ietf.org/html/draft-jivsov-ecc-compact-05] and is based on a
%% 1986 publication by Victor Miller in 'CRYPTO 85'. This method is believed to
%% be unpatentable. See [https://cr.yp.to/ecdh/patents.html] for more details.
%%
%% The implementation is done as a NIF linked against the system's libcrypto.

-module(ecc_compact).
-export([is_compact/1, generate_key/0, recover_key/1]).
-on_load(init/0).

-include_lib("public_key/include/public_key.hrl").

-define(APPNAME, ecc_compact).
-define(LIBNAME, ecc_compact).

-type private_key() :: #'ECPrivateKey'{}.
-type public_key() :: {#'ECPoint'{}, {namedCurve, ?secp256r1}}.
-type coordinate() :: <<_:256>>.
-type point() :: <<_:520>>.
-type compact_key() :: coordinate().

-export_type([public_key/0, private_key/0, compact_key/0]).

init() ->
    SoName = case code:priv_dir(?APPNAME) of
                 {error, bad_name} ->
                     case filelib:is_dir(filename:join(["..", priv])) of
                         true ->
                             filename:join(["..", priv, ?LIBNAME]);
                         _ ->
                             filename:join([priv, ?LIBNAME])
                     end;
                 Dir ->
                     filename:join(Dir, ?LIBNAME)
             end,
    erlang:load_nif(SoName, 0).

%% @doc Generate a NIST p-256 key that is compliant with the compactness
%% restrictions.
-spec generate_key() -> {ok, private_key(), compact_key()}.
generate_key() ->
    Key = public_key:generate_key({namedCurve,?secp256r1}),
    #'ECPrivateKey'{parameters=_Params, publicKey=PubKey} = Key,
    case is_compact_nif(PubKey) of
        true ->
            %% ok, get the X/Y coordinates
            <<4, X:32/binary, Y:32/binary>> = PubKey,
            case recover_int(X) of
                Y ->
                    {ok, Key, X};
                Z ->
                    %% this should never happen, but blow up dramatically if it does
                    erlang:error({key_recovery_failure, Key, X, Y, Z})
            end;
        false ->
            generate_key()
    end.

%% @doc Given the X coordinate of a public key from a compliant point on the
%% curve, return the public key.
-spec recover_key(compact_key()) -> public_key().
recover_key(X) when is_binary(X), byte_size(X) == 32 ->
    Y = recover_int(X),
    {#'ECPoint'{point = <<4, X:32/binary, Y:32/binary>>}, {namedCurve,
                                                           ?secp256r1}}.

-spec recover_int(compact_key()) -> coordinate().
recover_int(X) ->
    Y0 = recover_nif(X),
    case byte_size(Y0) < 32 of
        false ->
            Y0;
        true ->
            %% Sometimes the Y coordinate has leading 0s in its big-endian
            %% representation and thus the size of the bignum is less than
            %% 32 bytes. This leads the corresponding binary to be less than
            %% 32 bytes long and so we must pad it back up to 32 bytes
            %% manually here.
            Length = (32 - byte_size(Y0))*8,
            <<0:Length/integer-unsigned, Y0/binary>>
    end.

%% @doc Returns whether a given key is compliant with the compactness
%% restrictions. In the case that the key is compliant, also return the bare X
%% coordinate.
-spec is_compact(private_key() | public_key() | point()) ->
    {true, compact_key()} | false.
is_compact(#'ECPrivateKey'{parameters={namedCurve, ?secp256r1}, publicKey=PubKey}) ->
    is_compact(PubKey);
is_compact({#'ECPoint'{point=PubKey}, {namedCurve, ?secp256r1}}) ->
    is_compact(PubKey);
is_compact(<<4, X:32/binary, _Y:32/binary>> = PubKey) ->
    case is_compact_nif(PubKey) of
        true ->
            {true, X};
        false ->
            false
    end;
is_compact(_) ->
    erlang:error(badarg).


% This is just a simple place holder. It mostly shouldn't ever be called
% unless there was an unexpected error loading the NIF shared library.

is_compact_nif(_) ->
    not_loaded(?LINE).

recover_nif(_) ->
    not_loaded(?LINE).

not_loaded(Line) ->
    erlang:nif_error({not_loaded, [{module, ?MODULE}, {line, Line}]}).
