-module(socks5_proxy).
-export([start/0]).

-define(SOCKS5_PORT, 10087).
-define(PROXY_S_IP, "your.vps.ip.address").
-define(PROXY_S_PORT, 10099).
-define(PROXY_C_S_KEY, "your-secret-password").

start() ->
  {ok, Lsock} = gen_tcp:listen(?SOCKS5_PORT, [binary, {active, false}, {reuseaddr, true}]),
  io:format("listen sock: ~w~n", [Lsock]),
  accept(Lsock).

accept(Lsock) ->
  {ok, Sock} = gen_tcp:accept(Lsock),
  io:format("New SOCKS5 client connected: ~w~n", [Sock]),
  spawn(fun() -> handle_client(Sock) end),
  accept(Lsock).

handle_client(Sock) ->
  case handshake(Sock) of
    {ok, _AuthMethod} ->
      case handle_request(Sock) of
        {ok, Host, Port} ->
          io:format("SOCKS5 request: ~s:~p~n", [Host, Port]),
          forward_to_proxy_s(Sock, Host, Port);
        {error, Reason} ->
          io:format("SOCKS5 request error: ~p~n", [Reason]),
          gen_tcp:close(Sock)
      end;
    {error, Reason} ->
      io:format("SOCKS5 handshake error: ~p~n", [Reason]),
      gen_tcp:close(Sock)
  end.

handshake(Sock) ->
  case gen_tcp:recv(Sock, 2) of
    {ok, <<5, NMethods>>} ->
      case gen_tcp:recv(Sock, NMethods) of
        {ok, _Methods} ->
          gen_tcp:send(Sock, <<5, 0>>),
          {ok, no_auth};
        {error, Reason} ->
          {error, Reason}
      end;
    {error, Reason} ->
      {error, Reason}
  end.

handle_request(Sock) ->
  case gen_tcp:recv(Sock, 4) of
    {ok, <<5, Cmd, 0, Atyp>>} ->
      case Cmd of
        1 ->
          parse_address(Sock, Atyp);
        _ ->
          send_reply(Sock, 7, <<0,0,0,0>>, 0),
          {error, {unsupported_command, Cmd}}
      end;
    {error, Reason} ->
      {error, Reason}
  end.

parse_address(Sock, 1) ->
  case gen_tcp:recv(Sock, 6) of
    {ok, <<A1,A2,A3,A4,Port:16>>} ->
      Host = lists:flatten(io_lib:format("~p.~p.~p.~p", [A1,A2,A3,A4])),
      {ok, Host, Port};
    {error, Reason} ->
      {error, Reason}
  end;

parse_address(Sock, 3) ->
  case gen_tcp:recv(Sock, 1) of
    {ok, <<Len>>} ->
      case gen_tcp:recv(Sock, Len + 2) of
        {ok, <<HostBin:Len/binary, Port:16>>} ->
          Host = binary_to_list(HostBin),
          {ok, Host, Port};
        {error, Reason} ->
          {error, Reason}
      end;
    {error, Reason} ->
      {error, Reason}
  end;

parse_address(Sock, 4) ->
  case gen_tcp:recv(Sock, 18) of
    {ok, <<Addr:16/binary, Port:16>>} ->
      Host = format_ipv6(Addr),
      {ok, Host, Port};
    {error, Reason} ->
      {error, Reason}
  end;

parse_address(_Sock, Atyp) ->
  {error, {unsupported_address_type, Atyp}}.

format_ipv6(<<A:16,B:16,C:16,D:16,E:16,F:16,G:16,H:16>>) ->
  lists:flatten(io_lib:format("~.16b:~.16b:~.16b:~.16b:~.16b:~.16b:~.16b:~.16b", [A,B,C,D,E,F,G,H])).

send_reply(Sock, Rep, BndAddr, BndPort) ->
  Reply = <<5, Rep, 0, 1, BndAddr/binary, BndPort:16>>,
  gen_tcp:send(Sock, Reply).

encrypt_binary(Bin) ->
  Seeds = [29,220,39,154,155,183,36,101,240,97,60,232,246,60,81,32,173,79,158,172],
  fun F(_, <<>>) -> <<>>; F(Idx, Rest) ->
    Seed = lists:nth(Idx rem 20 + 1, Seeds),
    <<H, R/binary>> = Rest,
    Val = (H + Seed) rem 256,
    <<Val, (F(Idx + 1, R))/binary>>
  end(0, Bin).

tunnel(Sock, Tsock) ->
  Pid1 = spawn(fun F() ->
    case gen_tcp:recv(Sock, 0) of
      {ok, B} ->
        io:format("data from sock arrive ~w ~w ~w~n", [byte_size(B), Sock, Tsock]),
        case gen_tcp:send(Tsock, B) of
          ok -> F();
          {error, R} ->
            io:format("error from tsock: ~p ~w ~w~n", [R, Tsock, Sock]),
            gen_tcp:close(Tsock), gen_tcp:close(Sock)
        end;
      {error, R} ->
        io:format("error from sock: ~p ~w ~w~n", [R, Sock, Tsock]),
        gen_tcp:close(Sock), gen_tcp:close(Tsock)
    end end),
  gen_tcp:controlling_process(Sock, Pid1),

  Pid2 = spawn(fun F() ->
    case gen_tcp:recv(Tsock, 0) of
      {ok, B} ->
        io:format("data from tsock arrive ~w ~w ~w~n", [byte_size(B), Tsock, Sock]),
        case gen_tcp:send(Sock, B) of
          ok -> F();
          {error, R} ->
            io:format("error from sock: ~p ~w ~w~n", [R, Sock, Tsock]),
            gen_tcp:close(Sock), gen_tcp:close(Tsock)
        end;
      {error, R} ->
        io:format("error from tsock: ~p ~w ~w~n", [R, Tsock, Sock]),
        gen_tcp:close(Tsock), gen_tcp:close(Sock)
    end end),
  gen_tcp:controlling_process(Tsock, Pid2).

forward_to_proxy_s(ClientSock, Host, Port) ->
  case gen_tcp:connect(?PROXY_S_IP, ?PROXY_S_PORT, [binary, {active, false}, {packet, 4}]) of
    {ok, Ssock} ->
      io:format("connect to proxy server success: ~p ~w ~w~n", [?PROXY_S_IP, Ssock, ClientSock]),
      InitReq = {init, Host, Port, ?PROXY_C_S_KEY},
      ok = gen_tcp:send(Ssock, encrypt_binary(term_to_binary(InitReq))),
      {ok, Bin} = gen_tcp:recv(Ssock, 0),
      InitRsp = binary_to_term(Bin),
      io:format("recv init rsp from server: ~p ~w ~w~n", [InitRsp, Ssock, ClientSock]),

      case gen_tcp:send(ClientSock, <<5,0,0,1,0,0,0,0,0,0>>) of
        ok ->
          io:format("send browser established success: ~w ~w~n", [ClientSock, Ssock]),
          inet:setopts(ClientSock, [{packet, 0}]),
          tunnel(ClientSock, Ssock);
        {error, R} ->
          io:format("send browser established failed: ~p ~w ~w~n", [R, ClientSock, Ssock]),
          gen_tcp:close(ClientSock),
          gen_tcp:close(Ssock)
      end;
    {error, R} ->
      io:format("connect to proxy server failed: ~p ~w~n", [R, ClientSock]),
      send_reply(ClientSock, 1, <<0,0,0,0>>, 0),
      gen_tcp:close(ClientSock)
  end.
