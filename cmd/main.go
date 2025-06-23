package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
	"domain-security-checker/internal/api"
	"domain-security-checker/internal/checker"
	"domain-security-checker/internal/database"
	"domain-security-checker/internal/types"
)

func main() {
    var (
        mode     = flag.String("mode", "cli", "Mode: cli or server")
        domain   = flag.String("domain", "", "Domain to check")
        file     = flag.String("file", "", "File with domains")
        port     = flag.String("port", "8080", "Server port")
        timeout  = flag.Duration("timeout", 10*time.Second, "DNS timeout")
        verbose  = flag.Bool("verbose", false, "Verbose output")
        output   = flag.String("output", "", "Output to CSV file")
    )
    flag.Parse()

    db, err := database.New("domains.db")
    if err != nil {
        log.Fatalf("Database error: %v", err)
    }
    defer db.Close()

    domainChecker := checker.New(*timeout, *verbose, db)

    switch *mode {
    case "cli":
        if *domain != "" {
            runSingleCheck(domainChecker, *domain)
        } else if *file != "" {
            runBatchCheck(domainChecker, *file, *output)
        } else {
            runInteractiveMode(domainChecker)
        }
    case "server":
        runServer(domainChecker, *port)
    default:
        flag.Usage()
    }
}

func runSingleCheck(checker *checker.Checker, domain string) {
    result, err := checker.CheckDomain(domain)
    if err != nil {
        log.Fatalf("Error: %v", err)
    }
    printResult(result)
}

func runBatchCheck(checker *checker.Checker, filename, output string) {
    domains, err := readDomainsFromFile(filename)
    if err != nil {
        log.Fatalf("Error reading file: %v", err)
    }

    var outputFile *os.File
    if output != "" {
        outputFile, err = os.Create(output)
        if err != nil {
            log.Fatalf("Error creating output file: %v", err)
        }
        defer outputFile.Close()
        fmt.Fprintln(outputFile, "domain,hasMX,hasSPF,spfRecord,hasDMARC,dmarcRecord")
    } else {
        fmt.Println("domain,hasMX,hasSPF,spfRecord,hasDMARC,dmarcRecord")
    }

    for _, domain := range domains {
        result, err := checker.CheckDomain(domain)
        if err != nil {
            log.Printf("Error checking %s: %v", domain, err)
            continue
        }
        
        line := fmt.Sprintf("%s,%t,%t,\"%s\",%t,\"%s\"",
            result.Domain, result.HasMX, result.HasSPF, 
            result.SPFRecord, result.HasDMARC, result.DMARCRecord)
        
        if outputFile != nil {
            fmt.Fprintln(outputFile, line)
        } else {
            fmt.Println(line)
        }
    }
}

func runInteractiveMode(checker *checker.Checker) {
    fmt.Println("Enter domains (Ctrl+C to exit):")
    
    scanner := bufio.NewScanner(os.Stdin)
    for scanner.Scan() {
        domain := strings.TrimSpace(scanner.Text())
        if domain == "" {
            continue
        }
        
        result, err := checker.CheckDomain(domain)
        if err != nil {
            log.Printf("Error: %v", err)
            continue
        }
        
        printResult(result)
        fmt.Println("---")
    }
}

func runServer(checker *checker.Checker, port string) {
    handler := api.NewHandler(checker)
    log.Printf("Server starting on port %s", port)
    log.Printf("Endpoints:")
    log.Printf("  GET /check/{domain}")
    log.Printf("  GET /history/{domain}")
    log.Fatal(http.ListenAndServe(":"+port, handler))
}

func printResult(result *types.DomainResult) {
    fmt.Printf("Domain: %s\n", result.Domain)
    fmt.Printf("MX Records: %t\n", result.HasMX)
    fmt.Printf("SPF Record: %t (%s)\n", result.HasSPF, result.SPFRecord)
    fmt.Printf("DMARC Record: %t (%s)\n", result.HasDMARC, result.DMARCRecord)
    fmt.Printf("Checked: %s\n", result.CheckedAt.Format("2006-01-02 15:04:05"))
}

func readDomainsFromFile(filename string) ([]string, error) {
    file, err := os.Open(filename)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    var domains []string
    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        domain := strings.TrimSpace(scanner.Text())
        if domain != "" && !strings.HasPrefix(domain, "#") {
            domains = append(domains, domain)
        }
    }
    
    return domains, scanner.Err()
}