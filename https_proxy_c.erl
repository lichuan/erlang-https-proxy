-module(https_proxy_c).
-export([start/0]).

-define(PROXY_C_PORT, 10088).
-define(PROXY_S_IP, "your.vps.ip.address").
-define(PROXY_S_PORT, 10099).
-define(PROXY_C_S_KEY, "your-secret-password").

start() ->
  {ok, Lsock} = gen_tcp:listen(?PROXY_C_PORT, [binary, {packet, http}, {active, false}]),
  io:format("listen sock: ~w~n", [Lsock]),
  accept(Lsock).

tunnel(Sock, Tsock) ->
  Pid1 = spawn(fun F() ->
    case gen_tcp:recv(Sock, 0) of
      {ok, B} ->
        io:format("data from sock arrive ~w ~w ~w~n", [byte_size(B), Sock, Tsock]),
        case gen_tcp:send(Tsock, B) of
          ok -> F();
          {error, R} ->
            io:format("error from tsock: ~w ~w ~w~n", [R, Tsock, Sock]),
            gen_tcp:close(Tsock), gen_tcp:close(Sock)
        end;
      {error, R} ->
        io:format("error from sock: ~w ~w ~w~n", [R, Sock, Tsock]),
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
            io:format("error from sock: ~w ~w ~w~n", [R, Sock, Tsock]),
            gen_tcp:close(Sock), gen_tcp:close(Tsock)
        end;
      {error, R} ->
        io:format("error from tsock: ~w ~w ~w~n", [R, Tsock, Sock]),
        gen_tcp:close(Tsock), gen_tcp:close(Sock)
    end end),
  gen_tcp:controlling_process(Tsock, Pid2).

encrypt_binary(Bin) ->
  Seeds = [29,220,39,154,155,183,36,101,240,97,60,232,246,60,81,32,173,79,158,172],
  fun F(_, <<>>) -> <<>>; F(Idx, Rest) ->
    Seed = lists:nth(Idx rem 20 + 1, Seeds),
    <<H, R/binary>> = Rest,
    Val = (H + Seed) rem 256,
    <<Val, (F(Idx + 1, R))/binary>>
  end(0, Bin).

decrypt_binary(Bin) ->
  Seeds = [29,220,39,154,155,183,36,101,240,97,60,232,246,60,81,32,173,79,158,172],
  fun F(_, <<>>) -> <<>>; F(Idx, Rest) ->
    Seed = lists:nth(Idx rem 20 + 1, Seeds),
    <<H, R/binary>> = Rest,
    if
      H - Seed < 0 -> Val = 256 + H - Seed;
      true -> Val = H - Seed
    end,
    <<Val, (F(Idx + 1, R))/binary>>
  end(0, Bin).

recv_with_host(Sock, TargetHost) ->
  inet:setopts(Sock, [{active, once}]),
  receive
    {http, Sock, http_eoh} ->
      io:format("head end received: ~w ~w~n", [http_eoh, Sock]),
      inet:setopts(Sock, [{packet, 0}]),
      io:format("targethost................: ~s ~w~n", [TargetHost, Sock]),
      case gen_tcp:connect(?PROXY_S_IP, ?PROXY_S_PORT, [binary, {active, false}, {packet, 4}]) of
        {ok, Ssock} ->
          io:format("connect to proxy server success: ~p ~w ~w~n", [?PROXY_S_IP, Ssock, Sock]),
          InitReq = {init, TargetHost, 443, ?PROXY_C_S_KEY},
          ok = gen_tcp:send(Ssock, encrypt_binary(term_to_binary(InitReq))),
          {ok, Bin} = gen_tcp:recv(Ssock, 0),
          InitRsp = binary_to_term(Bin),
          io:format("recv init rsp from server: ~p ~w ~w~n", [InitRsp, Ssock, Sock]),
          case gen_tcp:send(Sock, "HTTP/1.1 200 Connection Established\r\n\r\n") of
            ok ->
              io:format("send browser established success: ~w ~w~n", [Sock, Ssock]),
              tunnel(Sock, Ssock);
            {error, R} ->
              io:format("send browser established failed: ~w ~w ~w~n", [R, Sock, Ssock]),
              gen_tcp:close(Sock), gen_tcp:close(Ssock)
          end;
        {error, R} ->
          io:format("connect to proxy server failed: ~p ~w ~w~n", [TargetHost, R, Sock]),
          gen_tcp:close(Sock)
      end;
    {http, Sock, Data} ->
      io:format("http data: ~w ~w~n", [Data, Sock]),
      recv_with_host(Sock, TargetHost);
    Other -> io:format("other in target: ~w ~w~n", [Other, Sock])
  end.

recv(Sock) ->
  inet:setopts(Sock, [{active, once}]),
  receive
    {http, Sock, {http_header, _, 'Host', _, Hostport} = Data} ->
      io:format("http data: ~p ~w~n", [Data, Sock]),
      [TargetHost|_] = string:split(Hostport, ":"),
      recv_with_host(Sock, TargetHost);
    {http, Sock, {http_error, R}} ->
      io:format("http error: ~w~n", [R]),
      gen_tcp:close(Sock);
    {http, Sock, Data} ->
      io:format("http data: ~p ~w~n", [Data, Sock]),
      recv(Sock);
    {tcp, Sock, Data} -> io:format("tcp data: ~w ~w~n", [Data, Sock]);
    {tcp_passive, Sock} -> io:format("tcp passive: ~w~n", [Sock]);
    {tcp_closed, Sock} ->
      io:format("tcp closed: ~w~n", [Sock]);
    {tcp_error, Sock, Reason} ->
      io:format("tcp error reason: ~w ~w~n", [Reason, Sock]),
      gen_tcp:close(Sock);
    Other -> io:format("other in recv: ~p ~w~n", [Other, Sock])
  end.

accept(Lsock) ->
  {ok, Sock} = gen_tcp:accept(Lsock),
  io:format("accept sock: ~w~n", [Sock]),
  Pid = spawn(fun() -> recv(Sock) end),
  gen_tcp:controlling_process(Sock, Pid),
  accept(Lsock).
