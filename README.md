# PowerShell-May-Cry

The tool adopts a methodology similar to that used by Invoke-Obfuscation for generating evasive PowerShell scripts. However, it extends this approach by integrating additional PowerShell evasion tools and techniques in a combinatorial manner to produce obfuscated scripts capable of potentially bypassing AMSI during execution.

In addition to offensive use cases, the tool can also benefit blue teams by serving as a source of test payloads. Security defenders can incorporate it into a testing pipeline to evaluate the effectiveness of their existing defenses and identify possible bypasses.

## How to Use

1. Simply clone this repo and run the command below
2. After each execution, folders corresponding to the number of combinations employed will be created with each folder containing the generated scripts name randomly. 
3. Additionally, a CSV file containing the exact tools that were combine to generate each script will be created for reporting and identification purposes.

## Limitations

Currently, including or excluding specific tools or techniques requires manually commenting or uncommenting obfuscation methods within the script. Future releases may introduce support for specifying obfuscation methods through command-line arguments for improved flexibility
