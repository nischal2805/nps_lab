# Universal Lab Manual Prompt

Copy and paste the block below to generate a lab manual for any code repository.
Replace `[REPO PATH OR URL]` with a local folder path or a GitHub URL.

---

## Prompt

```
You are a technical documentation engineer. Analyze the repository at [REPO PATH OR URL]
and generate a lab manual. Read every file in the codebase before writing anything.
Save the final output as lab.md in the project root.

---

Follow this exact structure:

# [Project Name] — Lab Manual

## Aim
Write 2–3 sentences. State what the tool does, the specific problem it solves,
and who uses it. Use plain, direct language. No buzzwords.

## Objectives
Write exactly 5 bullet points. Each point must have:
- A bold one-line title on the same line as the dash
- 2–3 sentences below it that mention actual file or module names from the repo
- Plain language — short sentences, no corporate phrasing

## Flowchart — Execution Pipeline
Mermaid flowchart TD. Rules:
- Include at least one decision branch using {Decision?} nodes
- Show both paths from each decision (e.g. yes/no, mode A/mode B)
- Max 12 nodes total
- Node labels must be 2–5 words, no special characters
- Show only the happy path plus the main branch decisions
- No error handling branches

Example branch style:
    B{Mode?} -->|static only| C[static_analyzer]
    B -->|live only| D[validate host]
    B -->|combined| C

## Architecture Diagram — System Design
Mermaid flowchart TD with subgraph blocks. Rules:
- Group related modules into subgraphs (e.g. Static Analysis, Live Probing, Dashboard)
- Must include at least 3 bidirectional arrows using <-->
- Must include at least one cross-subgraph connection (a module in one group
  connecting to a module in a different group)
- Must include at least one feedback arrow (a later module pointing back to an earlier one)
- External services (APIs, databases) use stadium shape: (["Name"])
- Storage nodes use cylinder shape: [("Name")]
- Arrow labels must be under 4 words
- No nested subgraphs
- No special characters in any label (no /, no ·, no —)

## Sequence Diagram — Component Interaction
Mermaid sequenceDiagram. Rules:
- Max 8 interactions
- Show the core runtime flow only
- Use -->> for return messages (dotted arrow)
- Message labels under 5 words each
- Name participants using short aliases

## MVP — What This Proposes
One short paragraph (3–4 sentences) explaining what is genuinely new about this
project compared to existing tools. Then write exactly 4 bullet points, each with:
- A bold one-line title
- 2–3 sentences explaining what specifically is novel, referencing the actual
  function or file name that implements it

Focus on: what existing tools cannot do, what new behaviour this introduces,
and what specific mechanism in the code makes it work.

## Application and Conclusion

### Applications
Write exactly 4 bullet points. Each is one sentence describing a real-world
scenario where this tool adds value. Be specific — name the mode, flag, or
feature that applies to each scenario.

### Conclusion
Write 3–4 sentences covering: what the project technically achieves, its current
limitations, and future scope. The future scope must come from actual unfinished
code or TODOs visible in the repository — do not invent it.

---

STRICT RULES — follow all of these or the output is wrong:
1. Read the entire codebase before writing a single word of output
2. Every module and function name in the text must exist in the actual repo
3. Diagrams must use only names from real files in the repo
4. No special characters in Mermaid labels: avoid / · — × ( ) inside node text
5. No nested subgraphs in any Mermaid diagram
6. The flowchart must have visible branches — a straight A→B→C→D line is not acceptable
7. The architecture diagram must not be unidirectional — it needs feedback arrows
   and cross-group connections
8. Write in plain English — short sentences, active voice, no buzzwords
9. Do not use phrases like: "demonstrates", "delivers", "enables teams to",
   "compliance-ready", "coherent fusion", "technically sound", "actionable"
10. No tables, no code snippets, no installation steps, no CLI commands
11. Total length must fit within 4 printed pages
12. Save output as lab.md in the project root
```

---

## What each section produces

| Section | Format | Key constraint |
|---|---|---|
| Aim | 2–3 plain sentences | No buzzwords |
| Objectives | 5 bullet points with bold titles | Real module names only |
| Flowchart | Mermaid flowchart TD | Must branch — no straight line |
| Architecture | Mermaid flowchart TD with subgraphs | Bidirectional + feedback arrows |
| Sequence | Mermaid sequenceDiagram | Max 8 steps |
| MVP | Para + 4 bullets | Real novel behaviour only |
| Application & Conclusion | 4 bullets + short para | Limitations from actual code |

## Tips for best results

- If the repo is large, add: "Focus on files in the main source folder, skip test files and docs."
- If you want a specific technology called out: add "Highlight the use of [technology]" at the end.
- If the diagrams look cluttered: add "Keep each subgraph to a maximum of 4 nodes."
- To adjust length: replace "4 printed pages" with your preferred length.
