package com.example.asiceverifier;

import java.nio.file.Path;
import java.nio.file.Paths;

public record Args(Path dir, boolean listOnly, boolean all, String one, Path configPath) {

    public static Args parse(String[] args) {
        Path dir = null;
        boolean list = false;
        boolean all = false;
        String one = null;
        Path cfg = null;

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--dir" -> {
                    if (i + 1 >= args.length) throw new IllegalArgumentException("Missing value for --dir");
                    dir = Paths.get(args[++i]);
                }
                case "--list" -> list = true;
                case "--all" -> all = true;
                case "--one" -> {
                    if (i + 1 >= args.length) throw new IllegalArgumentException("Missing value for --one");
                    one = args[++i];
                }
                case "--config" -> {
                    if (i + 1 >= args.length) throw new IllegalArgumentException("Missing value for --config");
                    cfg = Paths.get(args[++i]);
                }
                case "--help", "-h" -> printHelpAndExit();
                default -> throw new IllegalArgumentException("Unknown argument: " + args[i] + " (try --help)");
            }
        }

        if (dir == null) throw new IllegalArgumentException("Required: --dir <path> (try --help)");
        if (!list && one == null && !all) all = true; // default to all

        return new Args(dir, list, all, one, cfg);
    }

    private static void printHelpAndExit() {
        System.out.println("""
                ASiC-E (.asice) XAdES-T checks (fail-fast)

                Usage:
                  --dir <path>      directory with .asice files (required)
                  --list            list samples and exit
                  --all             verify all (default)
                  --one <n|file>    verify one by index (1..N) or by filename
                  --config <path>   override verifier.properties (optional)
                """);
        System.exit(0);
    }
}
