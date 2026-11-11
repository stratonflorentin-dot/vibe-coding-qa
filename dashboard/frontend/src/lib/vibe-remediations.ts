import type { Finding } from "@/types/api";

export interface VibeFixGuide {
  riskSummary: string;
  whyItHappens: string;
  fixTitle: string;
  fixLanguage: "sql" | "typescript" | "bash" | "json" | "env" | "text";
  codeSnippet: string;
  actionSteps: string[];
  aiPrompt: string;
}

function extractTableName(text: string): string | null {
  const match = text.match(/table\s+['"`]([^'"`]+)['"`]/i) || text.match(/\bpublic\.([a-zA-Z0-9_]+)\b/i);
  return match ? match[1] : null;
}

export function getVibeFixGuide(finding: Finding): VibeFixGuide {
  const rule = (finding.rule || "").toLowerCase();
  const message = finding.message || "";
  const suggestion = finding.suggestion || "";
  const file = finding.file || "unknown-file";
  const line = finding.line || 1;
  const tableName = extractTableName(message) || "your_table_name";
  const rawTable = tableName.includes(".") ? tableName : `public.${tableName}`;

  // 1. Missing RLS on database table
  if (rule.includes("table-without-rls") || rule.includes("missing-rls")) {
    return {
      riskSummary: `Anyone with your public Supabase/PostgREST anon key can read, modify, or delete every row in '${rawTable}'.`,
      whyItHappens: "When creating tables via migrations or AI prompts, Row Level Security (RLS) is disabled by default in PostgreSQL until explicitly turned on.",
      fixTitle: "Supabase / PostgreSQL RLS Migration",
      fixLanguage: "sql",
      codeSnippet: `-- 1. Turn on Row Level Security (RLS)\nALTER TABLE ${rawTable} ENABLE ROW LEVEL SECURITY;\n\n-- 2. Allow authenticated users to view only their own records\nCREATE POLICY "Users can read own ${tableName.replace("public.", "")}"\n  ON ${rawTable}\n  FOR SELECT\n  TO authenticated\n  USING (auth.uid() = user_id);\n\n-- 3. Allow users to insert records linked to their own ID\nCREATE POLICY "Users can insert own ${tableName.replace("public.", "")}"\n  ON ${rawTable}\n  FOR INSERT\n  TO authenticated\n  WITH CHECK (auth.uid() = user_id);`,
      actionSteps: [
        `Run the SQL script above in your Supabase SQL Editor or database migration.`,
        `Replace 'user_id' with your actual user reference column if named differently (e.g. 'owner_id' or 'created_by').`,
        `Test the query from an unauthenticated client to confirm rows are no longer exposed.`,
      ],
      aiPrompt: `I have a critical database vulnerability in my project: Table '${rawTable}' has no Row Level Security (RLS) enabled.
File/Location: ${file}:${line}
Issue: ${message}

Please generate the correct PostgreSQL / Supabase migration SQL to:
1. Enable ROW LEVEL SECURITY on '${rawTable}'.
2. Create granular SELECT, INSERT, UPDATE, and DELETE policies appropriate for this table.
3. Ensure unauthenticated public users cannot access or alter data.`,
    };
  }

  // 2. Policy exists but RLS is not enabled
  if (rule.includes("policy-without-rls-enabled")) {
    return {
      riskSummary: `You wrote RLS policies for '${rawTable}', but RLS itself is turned off! PostgreSQL ignores all policies until RLS is enabled.`,
      whyItHappens: "Creating a POLICY does not automatically enable RLS on the table; PostgreSQL requires an explicit ALTER TABLE ... ENABLE command.",
      fixTitle: "Activate RLS in SQL",
      fixLanguage: "sql",
      codeSnippet: `-- Turn on RLS so your existing policies take effect immediately\nALTER TABLE ${rawTable} ENABLE ROW LEVEL SECURITY;`,
      actionSteps: [
        `Execute the ALTER TABLE command in your Supabase SQL editor or migration runner.`,
        `Verify with: SELECT tablename, rowsecurity FROM pg_tables WHERE tablename = '${tableName.replace("public.", "")}';`,
      ],
      aiPrompt: `In my project, table '${rawTable}' has policies created, but Row Level Security is NOT enabled (policies have no effect).
Location: ${file}:${line}

Please write the migration to enable RLS on '${rawTable}' and verify that all current policies work as expected without locking out legitimate users.`,
    };
  }

  // 3. Client-side role update / Privilege escalation
  if (rule.includes("client-role-update") || rule.includes("editable-role-field")) {
    return {
      riskSummary: "Users can send an update request to change their own 'role' or 'is_admin' field, granting themselves full administrator rights.",
      whyItHappens: "AI code generators often bind form submissions or client inputs directly to database update queries (e.g., `supabase.from('profiles').update(formData)`).",
      fixTitle: "Strip Privileged Fields in Server / RLS",
      fixLanguage: "typescript",
      codeSnippet: `// Option A: In API Route / Server Action (destructure to drop protected fields)\nconst { role, is_admin, permissions, ...allowedFields } = req.body;\n\nawait supabase\n  .from('profiles')\n  .update(allowedFields)\n  .eq('id', currentUser.id);\n\n// Option B: Or enforce in Supabase RLS (disallow changing role column)\n-- CREATE POLICY "Users cannot change own role"\n--   ON public.profiles\n--   FOR UPDATE\n--   USING (auth.uid() = id)\n--   WITH CHECK (role = (SELECT role FROM public.profiles WHERE id = auth.uid()));`,
      actionSteps: [
        `Locate the update handler in ${file} at line ${line}.`,
        `Never pass raw user request bodies directly into database update queries.`,
        `Explicitly whitelist only the fields users are allowed to edit (like name, avatar, bio).`,
      ],
      aiPrompt: `There is a privilege escalation vulnerability in ${file}:${line}:
Issue: ${message}
Suggestion: ${suggestion}

Please refactor this update logic so that clients cannot modify privileged fields like 'role', 'is_admin', or permissions. Strip these fields on the server or enforce column-level security.`,
    };
  }

  // 4. Exposed Secrets / JWT / API Keys
  if (rule.includes("jwt-token") || rule.includes("secret") || rule.includes("client-side-secret") || rule.includes("committed-env")) {
    return {
      riskSummary: "A secret token or API key is exposed in source code. Anyone with access to the repo or client bundle can impersonate your system.",
      whyItHappens: "Hardcoding credentials during quick prototyping or prefixing private keys with `NEXT_PUBLIC_` or `VITE_`.",
      fixTitle: "Rotate & Move to Environment Variables",
      fixLanguage: "bash",
      codeSnippet: `# 1. Immediately rotate / invalidate this token in your provider dashboard!\n\n# 2. Add the secret to your local environment file:\n# in .env.local (do NOT commit this file):\nPRIVATE_SECRET_KEY="your-new-rotated-secret-here"\n\n# 3. Ensure your .gitignore contains:\n.env*.local\n.env`,
      actionSteps: [
        "Rotate the compromised credential immediately in your auth/cloud provider dashboard.",
        "Remove the literal string from the source code.",
        "Access the secret exclusively on the server side via process.env (never in frontend components).",
      ],
      aiPrompt: `We detected an exposed secret/token in our repository:
File: ${file}:${line}
Rule: ${finding.rule}
Message: ${message}

Please help me:
1. Replace the hardcoded token with a secure server-side environment variable call.
2. Ensure the secret is never bundled into client-side JavaScript.
3. Show me how to update .gitignore and configure environment variables safely.`,
    };
  }

  // 5. SQL Injection
  if (rule.includes("sql-injection") || rule.includes("sqli")) {
    return {
      riskSummary: "Unsanitized user input is directly concatenated into a SQL statement, enabling attackers to bypass authentication or dump the entire database.",
      whyItHappens: "Using template literals (`` `SELECT * FROM users WHERE id = ${id}` ``) instead of parameterized query arguments.",
      fixTitle: "Use Parameterized Queries",
      fixLanguage: "typescript",
      codeSnippet: `// ❌ INSECURE (concatenation / template literal):\n// const result = await db.query(\`SELECT * FROM items WHERE category = '\${category}'\`);\n\n// ✅ SECURE (parameterized placeholder):\nconst result = await db.query(\n  'SELECT * FROM items WHERE category = $1',\n  [category]\n);`,
      actionSteps: [
        `Open ${file} at line ${line}.`,
        "Replace any string interpolation with parameter binding placeholders ($1, ?, or named parameters).",
        "Never pass raw variables directly into database query strings.",
      ],
      aiPrompt: `A SQL injection risk was identified at ${file}:${line}:
Issue: ${message}

Please rewrite the query using parameterized statements or an ORM/query-builder call so user input is never concatenated directly into SQL text.`,
    };
  }

  // 6. SSRF (Server-Side Request Forgery)
  if (rule.includes("ssrf")) {
    return {
      riskSummary: "Server fetches user-provided URLs without validating whether they point to internal cloud metadata (169.254.169.254) or localhost.",
      whyItHappens: "Directly calling `fetch(userInputUrl)` or `axios.get(userUrl)` without validating protocol, resolving DNS, or filtering private IP ranges.",
      fixTitle: "Validate & Pin Target URL",
      fixLanguage: "typescript",
      codeSnippet: `// Validate protocol and reject private/internal IP ranges:\nconst parsed = new URL(targetUrl);\nif (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {\n  throw new Error('Only HTTP/HTTPS URLs are allowed');\n}\n\n// Reject metadata & localhost addresses\nconst forbidden = ['169.254.', '127.', '10.', '192.168.', 'localhost', '::1'];\nif (forbidden.some((prefix) => parsed.hostname.startsWith(prefix))) {\n  throw new Error('Private or internal addresses are prohibited');\n}`,
      actionSteps: [
        `Inspect the URL fetching code in ${file} at line ${line}.`,
        "Validate scheme (http/https only) and disallow user-provided credentials.",
        "Check DNS resolution to block private RFC1918 and cloud metadata IP ranges.",
      ],
      aiPrompt: `An SSRF risk was detected in ${file}:${line}:
Issue: ${message}

Please rewrite the URL fetch logic to enforce strict validation against private IP addresses, cloud metadata endpoints (169.254.169.254), and disallowed URL schemes.`,
    };
  }

  // 7. General fallback for all other rules
  const steps: string[] = [];
  if (suggestion) {
    steps.push(suggestion);
  }
  steps.push(`Review the code at ${file}:${line}.`);
  steps.push("Rerun the scan after applying the change to verify the finding clears.");

  return {
    riskSummary: message || `Security or quality issue flagged by the ${finding.module} scanner.`,
    whyItHappens: `Common pitfall detected by rule '${finding.rule}'.`,
    fixTitle: "Recommended Remediation",
    fixLanguage: "typescript",
    codeSnippet: suggestion ? `// Recommendation:\n// ${suggestion.replace(/\n/g, "\n// ")}` : `// Review and refactor ${file}:${line} to comply with rule '${finding.rule}'.`,
    actionSteps: steps,
    aiPrompt: `Please fix the following ${finding.severity.toUpperCase()} issue in my project:
- Rule: ${finding.rule} (${finding.module})
- Location: ${file}:${line}
- Description: ${message}
- Suggested Fix: ${suggestion || "Apply safe coding best practices"}

Inspect the code around ${file}:${line} and provide the complete, safe implementation.`,
  };
}
