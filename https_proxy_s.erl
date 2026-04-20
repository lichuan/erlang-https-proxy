-module(https_proxy_s).
-export([start/0]).

-define(PROXY_S_PORT, 10099).
-define(PROXY_C_S_KEY, "your-secret-password").

start() ->
  {ok, Lsock} = gen_tcp:listen(?PROXY_S_PORT, [binary, {packet, 4}, {active, false}, {reuseaddr, true}]),
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

recv(Sock) ->
  inet:setopts(Sock, [{active, once}]),
  receive
    {tcp, Sock, Bin} ->
      Data = decrypt_binary(Bin),
      InitReq = {init, TargetHost, 443, Proxy_CS_key} = binary_to_term(Data),
      case Proxy_CS_key of
        ?PROXY_C_S_KEY ->
          io:format("recv init req from proxy clientt: ~p ~w~n", [InitReq, Sock]),
          case gen_tcp:connect(TargetHost, 443, [binary, {active, false}, {packet, 0}]) of
            {ok, Tsock} ->
              io:format("connect to target host success: ~p ~w ~w~n", [TargetHost, Tsock, Sock]),
              InitRsp = {init, TargetHost, ok},
              ok = gen_tcp:send(Sock, term_to_binary(InitRsp)),
              tunnel(Sock, Tsock);
            {error, R} ->
              io:format("connect to target host failed: ~w ~p ~w~n", [R, TargetHost, Sock]),
              gen_tcp:close(Sock)
          end;
        _ ->
          io:format("proxy cs key not match: ~w~n", [Sock]),
          gen_tcp:close(Sock)
      end;
    {tcp_passive, Sock} -> io:format("tcp passive: ~w~n", [Sock]);
    {tcp_closed, Anysock} ->
      io:format("tcp closed: ~w ~w~n", [Sock, Anysock]),
      gen_tcp:close(Sock);
    {tcp_error, Sock, Reason} -> io:format("tcp error reason: ~w ~w~n", [Reason, Sock]);
    Other -> io:format("other in recv: ~p ~w~n", [Other, Sock])
  end.

accept(Lsock) ->
  {ok, Sock} = gen_tcp:accept(Lsock),
  io:format("accept sock: ~w~n", [Sock]),
  Pid = spawn(fun() -> recv(Sock) end),
  gen_tcp:controlling_process(Sock, Pid),
  accept(Lsock).
