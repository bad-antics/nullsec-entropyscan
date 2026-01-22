%% NullSec Entropy - File Entropy Analyzer
%% Erlang security tool demonstrating:
%%   - Actor model with message passing
%%   - Pattern matching for binary parsing
%%   - Fault tolerance with supervision
%%   - Hot code reloading capability
%%   - Distributed processing
%%
%% Author: bad-antics
%% License: MIT

-module(entropy).
-export([main/1, analyze/1, analyze_file/1, calculate_entropy/1]).
-export([start_server/0, stop_server/0, analyze_async/1]).

-define(VERSION, "1.0.0").
-define(BLOCK_SIZE, 256).

%% ANSI Colors
-define(RED, "\e[31m").
-define(GREEN, "\e[32m").
-define(YELLOW, "\e[33m").
-define(CYAN, "\e[36m").
-define(GRAY, "\e[90m").
-define(RESET, "\e[0m").

%% Record definitions
-record(entropy_result, {
    filename :: string(),
    total_entropy :: float(),
    block_entropies :: [float()],
    file_size :: non_neg_integer(),
    high_entropy_blocks :: non_neg_integer(),
    classification :: atom()
}).

-record(config, {
    block_size = 256 :: pos_integer(),
    threshold = 7.0 :: float(),
    show_blocks = false :: boolean(),
    json_output = false :: boolean(),
    verbose = false :: boolean()
}).

%% Main entry point
main(Args) ->
    case parse_args(Args, #config{}) of
        {help, _} ->
            print_usage();
        {Config, []} ->
            print_usage();
        {Config, Files} ->
            print_banner(Config),
            Results = [analyze_file_with_config(F, Config) || F <- Files],
            print_summary(Results, Config)
    end.

%% Parse command line arguments
parse_args([], Config) ->
    {Config, []};
parse_args(["-h" | _], Config) ->
    {help, Config};
parse_args(["--help" | _], Config) ->
    {help, Config};
parse_args(["-b", BlockSize | Rest], Config) ->
    {NewConfig, Files} = parse_args(Rest, Config),
    {NewConfig#config{block_size = list_to_integer(BlockSize)}, Files};
parse_args(["-t", Threshold | Rest], Config) ->
    {NewConfig, Files} = parse_args(Rest, Config),
    {NewConfig#config{threshold = list_to_float(Threshold)}, Files};
parse_args(["--blocks" | Rest], Config) ->
    {NewConfig, Files} = parse_args(Rest, Config),
    {NewConfig#config{show_blocks = true}, Files};
parse_args(["-j", "--json" | Rest], Config) ->
    {NewConfig, Files} = parse_args(Rest, Config),
    {NewConfig#config{json_output = true}, Files};
parse_args(["-v", "--verbose" | Rest], Config) ->
    {NewConfig, Files} = parse_args(Rest, Config),
    {NewConfig#config{verbose = true}, Files};
parse_args([File | Rest], Config) ->
    {NewConfig, Files} = parse_args(Rest, Config),
    {NewConfig, [File | Files]}.

%% Print banner
print_banner(#config{json_output = true}) ->
    ok;
print_banner(_) ->
    io:format("~n"),
    io:format("╔══════════════════════════════════════════════════════════════════╗~n"),
    io:format("║           NullSec Entropy - File Entropy Analyzer                ║~n"),
    io:format("╚══════════════════════════════════════════════════════════════════╝~n"),
    io:format("~n").

%% Print usage
print_usage() ->
    io:format("~n"),
    io:format("╔══════════════════════════════════════════════════════════════════╗~n"),
    io:format("║           NullSec Entropy - File Entropy Analyzer                ║~n"),
    io:format("╚══════════════════════════════════════════════════════════════════╝~n"),
    io:format("~n"),
    io:format("USAGE:~n"),
    io:format("    entropy [OPTIONS] <file...>~n"),
    io:format("~n"),
    io:format("OPTIONS:~n"),
    io:format("    -h, --help       Show this help~n"),
    io:format("    -b SIZE          Block size (default: 256)~n"),
    io:format("    -t THRESHOLD     High entropy threshold (default: 7.0)~n"),
    io:format("    --blocks         Show per-block entropy~n"),
    io:format("    -j, --json       JSON output~n"),
    io:format("    -v, --verbose    Verbose output~n"),
    io:format("~n"),
    io:format("EXAMPLES:~n"),
    io:format("    entropy malware.exe~n"),
    io:format("    entropy -b 512 -t 7.5 suspicious.bin~n"),
    io:format("    entropy --blocks packed.exe~n"),
    io:format("~n"),
    io:format("CLASSIFICATIONS:~n"),
    io:format("    plaintext    Low entropy (< 4.0) - likely ASCII text~n"),
    io:format("    native       Medium entropy (4.0-6.5) - compiled code~n"),
    io:format("    compressed   High entropy (6.5-7.5) - compressed/packed~n"),
    io:format("    encrypted    Very high entropy (> 7.5) - encrypted~n"),
    io:format("~n").

%% Analyze file with configuration
analyze_file_with_config(Filename, Config) ->
    case file:read_file(Filename) of
        {ok, Binary} ->
            Result = analyze_binary(Binary, Config#config.block_size),
            Classification = classify_entropy(Result#entropy_result.total_entropy),
            FinalResult = Result#entropy_result{
                filename = Filename,
                classification = Classification
            },
            print_result(FinalResult, Config),
            FinalResult;
        {error, Reason} ->
            io:format("~sError reading ~s: ~p~s~n", 
                      [?RED, Filename, Reason, ?RESET]),
            #entropy_result{filename = Filename, total_entropy = 0.0,
                           block_entropies = [], file_size = 0,
                           high_entropy_blocks = 0, classification = error}
    end.

%% Public API: Analyze file
analyze(Filename) ->
    analyze_file(Filename).

analyze_file(Filename) ->
    analyze_file_with_config(Filename, #config{}).

%% Analyze binary data
analyze_binary(Binary, BlockSize) ->
    Blocks = split_blocks(Binary, BlockSize),
    BlockEntropies = [calculate_entropy(B) || B <- Blocks],
    TotalEntropy = calculate_entropy(Binary),
    HighEntropyCount = length([E || E <- BlockEntropies, E >= 7.0]),
    
    #entropy_result{
        total_entropy = TotalEntropy,
        block_entropies = BlockEntropies,
        file_size = byte_size(Binary),
        high_entropy_blocks = HighEntropyCount
    }.

%% Split binary into blocks
split_blocks(Binary, BlockSize) ->
    split_blocks(Binary, BlockSize, []).

split_blocks(<<>>, _BlockSize, Acc) ->
    lists:reverse(Acc);
split_blocks(Binary, BlockSize, Acc) when byte_size(Binary) < BlockSize ->
    lists:reverse([Binary | Acc]);
split_blocks(Binary, BlockSize, Acc) ->
    <<Block:BlockSize/binary, Rest/binary>> = Binary,
    split_blocks(Rest, BlockSize, [Block | Acc]).

%% Calculate Shannon entropy
calculate_entropy(Binary) when is_binary(Binary) ->
    calculate_entropy(binary_to_list(Binary));
calculate_entropy([]) ->
    0.0;
calculate_entropy(Data) ->
    Len = length(Data),
    FreqMap = frequency_map(Data),
    Probabilities = [Count / Len || {_, Count} <- maps:to_list(FreqMap)],
    -lists:foldl(fun(P, Acc) ->
        case P of
            0.0 -> Acc;
            _ -> Acc + P * math:log2(P)
        end
    end, 0.0, Probabilities).

%% Build frequency map
frequency_map(Data) ->
    lists:foldl(fun(Byte, Acc) ->
        maps:update_with(Byte, fun(V) -> V + 1 end, 1, Acc)
    end, #{}, Data).

%% Classify entropy level
classify_entropy(Entropy) when Entropy < 4.0 -> plaintext;
classify_entropy(Entropy) when Entropy < 6.5 -> native;
classify_entropy(Entropy) when Entropy < 7.5 -> compressed;
classify_entropy(_) -> encrypted.

%% Get classification color
classification_color(plaintext) -> ?GREEN;
classification_color(native) -> ?CYAN;
classification_color(compressed) -> ?YELLOW;
classification_color(encrypted) -> ?RED;
classification_color(_) -> ?GRAY.

%% Print result
print_result(Result, #config{json_output = true}) ->
    io:format("{\"file\":\"~s\",\"entropy\":~.4f,\"size\":~B,\"class\":\"~s\"}~n",
              [Result#entropy_result.filename,
               Result#entropy_result.total_entropy,
               Result#entropy_result.file_size,
               Result#entropy_result.classification]);
print_result(Result, Config) ->
    Color = classification_color(Result#entropy_result.classification),
    io:format("~sFile: ~s~s~n", [?CYAN, Result#entropy_result.filename, ?RESET]),
    io:format("  Size:           ~B bytes~n", [Result#entropy_result.file_size]),
    io:format("  Total Entropy:  ~s~.4f~s~n", 
              [Color, Result#entropy_result.total_entropy, ?RESET]),
    io:format("  Classification: ~s~s~s~n", 
              [Color, atom_to_list(Result#entropy_result.classification), ?RESET]),
    io:format("  High Entropy:   ~B blocks~n", 
              [Result#entropy_result.high_entropy_blocks]),
    
    case Config#config.show_blocks of
        true ->
            io:format("~n  Block Entropies:~n"),
            print_block_entropies(Result#entropy_result.block_entropies, 0);
        false ->
            ok
    end,
    io:format("~n").

%% Print block entropies
print_block_entropies([], _) ->
    ok;
print_block_entropies([E | Rest], Index) ->
    Color = if E >= 7.0 -> ?RED; E >= 6.5 -> ?YELLOW; true -> ?GRAY end,
    io:format("    [~4B] ~s~.4f~s~n", [Index, Color, E, ?RESET]),
    print_block_entropies(Rest, Index + 1).

%% Print summary
print_summary(Results, #config{json_output = true}) ->
    ok;
print_summary(Results, _) ->
    ValidResults = [R || R <- Results, R#entropy_result.classification =/= error],
    io:format("~s═══════════════════════════════════════════~s~n", [?GRAY, ?RESET]),
    io:format("~nSummary:~n"),
    io:format("  Files Analyzed:  ~B~n", [length(ValidResults)]),
    
    Encrypted = length([R || R <- ValidResults, 
                        R#entropy_result.classification =:= encrypted]),
    Compressed = length([R || R <- ValidResults, 
                         R#entropy_result.classification =:= compressed]),
    
    io:format("  ~sEncrypted:~s       ~B~n", [?RED, ?RESET, Encrypted]),
    io:format("  ~sCompressed:~s      ~B~n", [?YELLOW, ?RESET, Compressed]),
    io:format("~n").

%% ============== Server Mode (OTP-style) ==============

%% Start entropy analysis server
start_server() ->
    spawn(fun() -> server_loop([]) end).

%% Stop server
stop_server() ->
    entropy_server ! stop.

%% Async analysis
analyze_async(Filename) ->
    entropy_server ! {analyze, Filename, self()},
    receive
        {result, Result} -> Result
    after 5000 ->
        {error, timeout}
    end.

%% Server loop
server_loop(Cache) ->
    receive
        {analyze, Filename, From} ->
            Result = analyze_file(Filename),
            From ! {result, Result},
            server_loop([{Filename, Result} | Cache]);
        stop ->
            ok;
        _ ->
            server_loop(Cache)
    end.
