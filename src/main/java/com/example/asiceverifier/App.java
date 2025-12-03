package com.example.asiceverifier;

import org.w3c.dom.Document;

import java.nio.file.*;
import java.util.*;
import java.io.IOException;

public final class App {

    public static void main(String[] argv) {
        try {
            run(argv);
        } catch (VerificationException ve) {

            System.out.println("[ERROR] " + ve.code() + " - " + ve.getMessage());
            System.exit(2);
        } catch (IllegalArgumentException iae) {
            System.out.println("[ERROR] ARGS - " + iae.getMessage());
            printHelp();
            System.exit(2);
        } catch (Exception e) {
            System.out.println("[ERROR] UNEXPECTED - " + e.getClass().getSimpleName() + ": " + e.getMessage());
            System.exit(3);
        }
    }

    private static void run(String[] argv) throws Exception {
        ArgsParsed args = parseArgs(argv);

        if (args.dir == null) {
            throw new IllegalArgumentException("Missing --dir \"C:\\path\\to\\samples\"");
        }
        if (!Files.exists(args.dir) || !Files.isDirectory(args.dir)) {
            throw new IllegalArgumentException("Directory does not exist: " + args.dir);
        }

        List<Path> files = listSampleFiles(args.dir);

        if (args.list) {
            printList(files);
            return;
        }

        if (files.isEmpty()) {
            System.out.println("No samples found in: " + args.dir);
            return;
        }

        // config
        Config cfg = (args.configPath != null) ? Config.load(args.configPath) : Config.load(null);

        AsiceReader reader = new AsiceReader();
        XadesTVerifier verifier = new XadesTVerifier();

        // --one: 
        if (args.oneIndex != null) {
            int idx = args.oneIndex;
            if (idx < 1 || idx > files.size()) {
                throw new IllegalArgumentException("--one must be between 1 and " + files.size() + ", got " + idx);
            }

            Path target = files.get(idx - 1);
            Document doc = reader.readSignatureXml(target);
            verifier.verify(doc, cfg);
            System.out.println("[OK] " + target.getFileName());
            return;
        }

        // --all: 
        boolean all = args.all || (!args.list && args.oneIndex == null);
        if (all) {
            boolean anyError = false;

            for (Path p : files) {
                try {
                    Document doc = reader.readSignatureXml(p);
                    verifier.verify(doc, cfg);
                    System.out.println("[OK] " + p.getFileName());
                } catch (VerificationException ve) {
                    anyError = true;
                    System.out.println("[ERROR] " + ve.code() + " - " + ve.getMessage() + " (file=" + p.getFileName() + ")");
                    
                }
            }

            if (anyError) System.exit(2);
            return;
        }

        printHelp();
    }

    private static List<Path> listSampleFiles(Path dir) throws IOException {
        List<Path> out = new ArrayList<>();
        try (var s = Files.list(dir)) {
            s.filter(Files::isRegularFile)
                    .filter(p -> {
                        String n = p.getFileName().toString().toLowerCase(Locale.ROOT);
                        return n.endsWith(".asice") || n.endsWith(".zip");
                    })
                    .forEach(out::add);
        }
        out.sort(Comparator.comparing(p -> p.getFileName().toString(), String.CASE_INSENSITIVE_ORDER));
        return out;
    }

    private static void printList(List<Path> files) {
        System.out.println("Samples (.asice):");
        for (int i = 0; i < files.size(); i++) {
            System.out.printf("  %2d) %s%n", i + 1, files.get(i).getFileName());
        }
    }

    private static void printHelp() {
        System.out.println("Usage:");
        System.out.println("  java -jar target/asice-verifier-1.0.0.jar --dir \"C:\\path\\to\\samples\" [--list|--all|--one N] [--config \"path\\to\\verifier.properties\"]");
        System.out.println();
        System.out.println("Options:");
        System.out.println("  --dir <path>       Folder with .asice samples");
        System.out.println("  --list             Print numbered list of samples");
        System.out.println("  --one <N>          Verify only sample N (1-based)");
        System.out.println("  --all              Verify all samples (default if no mode specified)");
        System.out.println("  --config <path>    Path to verifier.properties (optional)");
    }

    private static final class ArgsParsed {
        Path dir;
        boolean list;
        boolean all;
        Integer oneIndex;
        Path configPath;
    }

    private static ArgsParsed parseArgs(String[] argv) {
        ArgsParsed a = new ArgsParsed();
        List<String> args = Arrays.asList(argv);

        for (int i = 0; i < args.size(); i++) {
            String t = args.get(i);

            switch (t) {
                case "--help":
                case "-h":
                    printHelp();
                    System.exit(0);
                    break;

                case "--dir":
                    if (i + 1 >= args.size()) throw new IllegalArgumentException("Missing value after --dir");
                    a.dir = Paths.get(args.get(++i));
                    break;

                case "--list":
                    a.list = true;
                    break;

                case "--all":
                    a.all = true;
                    break;

                case "--one":
                    if (i + 1 >= args.size()) throw new IllegalArgumentException("Missing value after --one");
                    try {
                        a.oneIndex = Integer.parseInt(args.get(++i));
                    } catch (NumberFormatException nfe) {
                        throw new IllegalArgumentException("Invalid --one value, must be integer");
                    }
                    break;

                case "--config":
                    if (i + 1 >= args.size()) throw new IllegalArgumentException("Missing value after --config");
                    a.configPath = Paths.get(args.get(++i));
                    break;

                default:
                    throw new IllegalArgumentException("Unknown argument: " + t);
            }
        }

        int modes = (a.list ? 1 : 0) + (a.all ? 1 : 0) + (a.oneIndex != null ? 1 : 0);
        if (modes > 1) {
            throw new IllegalArgumentException("Choose only one mode: --list OR --all OR --one");
        }

        return a;
    }
}
