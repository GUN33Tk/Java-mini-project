
import java.util.*;
import java.net.*;
import java.io.*;

public class URLChecker {

    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);

        System.out.println("=== Advanced URL Safety Checker ===");
        System.out.print("Enter a URL: ");
        String url = sc.nextLine();

        String apiKey = "// Add your VirusTotal API key"; 

        boolean vtWorked = checkWithVirusTotal(url, apiKey);

        if (!vtWorked) {
            System.out.println("\n⚠️ Falling back to local heuristic analysis...\n");
            checkURL(url);
        }
    }

    // VIRUSTOTAL CHECK (FIXED)
    public static boolean checkWithVirusTotal(String url, String apiKey) {
        try {
            String encodedUrl = Base64.getUrlEncoder()
                    .withoutPadding()
                    .encodeToString(url.getBytes());

            String requestUrl = "https://www.virustotal.com/api/v3/urls/" + encodedUrl;

            HttpURLConnection conn = (HttpURLConnection) new URL(requestUrl).openConnection();
            conn.setRequestMethod("GET");
            conn.setRequestProperty("x-apikey", apiKey);

            int responseCode = conn.getResponseCode();

            if (responseCode == 200) {
                BufferedReader in = new BufferedReader(
                        new InputStreamReader(conn.getInputStream()));

                String inputLine;
                StringBuilder response = new StringBuilder();

                while ((inputLine = in.readLine()) != null) {
                    response.append(inputLine);
                }
                in.close();

                String result = response.toString();

                System.out.println("\n--- VirusTotal Result ---");

                // Extract malicious count safely
                int maliciousIndex = result.indexOf("\"malicious\":");

                if (maliciousIndex != -1) {
                    int start = maliciousIndex + 12;
                    int end = result.indexOf(",", start);

                    int maliciousCount = Integer.parseInt(
                            result.substring(start, end).trim()
                    );

                    if (maliciousCount > 0) {
                        System.out.println("🚨 MALICIOUS (flagged by " + maliciousCount + " engines)");
                    } else {
                        System.out.println("✅ SAFE (no engines flagged)");
                    }

                    return true; // VT worked
                } else {
                    System.out.println("Could not parse VirusTotal response.");
                    return false;
                }

            } else {
                System.out.println("No data found on VirusTotal.");
                return false;
            }

        } catch (Exception e) {
            System.out.println("Error connecting to VirusTotal.");
            return false;
        }
    }

    // LOCAL HEURISTIC CHECK
    public static void checkURL(String url) {
        int score = 0;
        List<String> reasons = new ArrayList<>();

        url = url.toLowerCase();

        if (url.length() > 75) {
            score++;
            reasons.add("URL is too long");
        }

        String[] keywords = {"login", "verify", "bank", "secure", "update", "free", "bonus", "account"};
        for (String word : keywords) {
            if (url.contains(word)) {
                score++;
                reasons.add("Contains suspicious keyword: " + word);
                break;
            }
        }

        if (url.contains("@")) {
            score++;
            reasons.add("Contains '@' symbol");
        }

        if (url.matches(".*\\d+\\.\\d+\\.\\d+\\.\\d+.*")) {
            score++;
            reasons.add("Uses IP address instead of domain");
        }

        if (!url.startsWith("https")) {
            score++;
            reasons.add("Does not use HTTPS");
        }

        int index = url.indexOf("//");
        if (index != -1 && index + 2 < url.length()) {
            if (url.substring(index + 2).contains("//")) {
                score++;
                reasons.add("Multiple '//' detected");
            }
        }

        int dotCount = url.length() - url.replace(".", "").length();
        if (dotCount > 4) {
            score++;
            reasons.add("Too many dots");
        }

        int hyphenCount = url.length() - url.replace("-", "").length();
        if (hyphenCount > 2) {
            score++;
            reasons.add("Too many hyphens");
        }

        String[] shorteners = {"bit.ly", "tinyurl.com", "goo.gl", "t.co"};
        for (String s : shorteners) {
            if (url.contains(s)) {
                score++;
                reasons.add("URL shortener used: " + s);
                break;
            }
        }

        String[] tlds = {".tk", ".ml", ".ga", ".cf", ".xyz"};
        for (String tld : tlds) {
            if (url.endsWith(tld)) {
                score++;
                reasons.add("Suspicious TLD: " + tld);
                break;
            }
        }

        if (url.indexOf("http") > 7) {
            score++;
            reasons.add("'http' found inside domain");
        }

        if (isTyposquatting(url, reasons)) {
            score++;
        }

        System.out.println("\n--- Heuristic Result ---");

        if (score >= 4) {
            System.out.println("🚨 HIGHLY SUSPICIOUS");
        } else if (score >= 2) {
            System.out.println("⚠️ SUSPICIOUS");
        } else {
            System.out.println("✅ SAFE");
        }

        System.out.println("\nRisk Score: " + score);
        System.out.println("\nReasons:");
        for (String r : reasons) {
            System.out.println("- " + r);
        }
    }

    // Typosquatting Detection
    public static boolean isTyposquatting(String url, List<String> reasons) {
        String domain = extractDomain(url);

        String normalized = domain
                .replace('0', 'o')
                .replace('1', 'l')
                .replace('3', 'e')
                .replace('5', 's');

        String[] popular = {"google", "facebook", "amazon", "microsoft", "apple"};

        for (String legit : popular) {
            if (normalized.contains(legit) && !domain.contains(legit)) {
                reasons.add("Typosquatting detected: " + legit);
                return true;
            }
        }

        return false;
    }

    // Extract domain
    public static String extractDomain(String url) {
        url = url.replace("https://", "").replace("http://", "");
        int slash = url.indexOf('/');
        if (slash != -1) url = url.substring(0, slash);
        return url;
    }
}