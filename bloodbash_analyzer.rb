##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
    include Msf::Auxiliary::Scanner  # For scanning/reporting capabilities
    include Msf::Auxiliary::Report   # For reporting findings to Metasploit DB
  
    def initialize(info = {})
      super(update_info(info,
        'Name'           => 'BloodBash SharpHound Offline Analyzer',
        'Description'    => %q{
          This module wraps the BloodBash Python script to analyze SharpHound JSON files offline.
          It detects AD attack paths, misconfigurations (e.g., ADCS ESC vulnerabilities, dangerous permissions),
          and other vulnerabilities. Results are displayed and can be reported to the Metasploit database.
          Requires BloodBash.py and dependencies (NetworkX, Rich) installed on the system.
        },
        'License'        => MSF_LICENSE,
        'Author'         => ['Your Name'],  # Replace with your name or 'BloodBash Team'
        'References'     => [
          ['URL', 'https://github.com/ly4k/BloodHound'],  # Reference to SharpHound/BloodHound
          ['URL', 'https://github.com/YourRepo/BloodBash']  # Replace with actual repo if public
        ],
        'Platform'       => 'ruby',
        'Arch'           => ARCH_RUBY,
      ))
  
      register_options([
        OptString.new('BLOODBASH_PATH', [true, 'Path to BloodBash.py script', '/path/to/BloodBash.py']),
        OptString.new('JSON_DIR', [true, 'Directory containing SharpHound JSON files', '/tmp/sharphound_jsons']),
        OptBool.new('ALL_CHECKS', [false, 'Run all analyses (equivalent to --all)', false]),
        OptBool.new('SHORTEST_PATHS', [false, 'Compute shortest paths to high-value targets', false]),
        OptBool.new('DANGEROUS_PERMISSIONS', [false, 'Check dangerous permissions', false]),
        OptBool.new('ADCS', [false, 'Check ADCS ESC vulnerabilities', false]),
        OptBool.new('GPO_ABUSE', [false, 'Check GPO abuse risks', false]),
        OptBool.new('DCSYNC', [false, 'Check DCSync rights', false]),
        OptBool.new('RBCD', [false, 'Check RBCD configurations', false]),
        OptBool.new('SESSIONS', [false, 'Check session/local admin summaries', false]),
        OptBool.new('KERBEROASTABLE', [false, 'Check Kerberoastable accounts', false]),
        OptBool.new('AS_REP_ROASTABLE', [false, 'Check AS-REP roastable accounts', false]),
        OptBool.new('SID_HISTORY', [false, 'Check SID history abuse', false]),
        OptBool.new('VERBOSE', [false, 'Enable verbose summary', false]),
        OptBool.new('FAST', [false, 'Enable fast mode (skip heavy computations)', false]),
        OptString.new('DOMAIN', [false, 'Filter by domain (e.g., lab.local)', nil]),
        OptBool.new('INDIRECT', [false, 'Include indirect paths/permissions', false]),
        OptString.new('EXPORT', [false, 'Export format (md, json, html, csv)', nil]),
        OptString.new('DB_PATH', [false, 'SQLite DB path for persistence', nil]),
      ])
    end
  
    def run
      # Build command arguments from datastore options
      cmd = ['python3', datastore['BLOODBASH_PATH'], datastore['JSON_DIR']]
      cmd << '--all' if datastore['ALL_CHECKS']
      cmd << '--shortest-paths' if datastore['SHORTEST_PATHS']
      cmd << '--dangerous-permissions' if datastore['DANGEROUS_PERMISSIONS']
      cmd << '--adcs' if datastore['ADCS']
      cmd << '--gpo-abuse' if datastore['GPO_ABUSE']
      cmd << '--dcsync' if datastore['DCSYNC']
      cmd << '--rbcd' if datastore['RBCD']
      cmd << '--sessions' if datastore['SESSIONS']
      cmd << '--kerberoastable' if datastore['KERBEROASTABLE']
      cmd << '--as-rep-roastable' if datastore['AS_REP_ROASTABLE']
      cmd << '--sid-history' if datastore['SID_HISTORY']
      cmd << '--verbose' if datastore['VERBOSE']
      cmd << '--fast' if datastore['FAST']
      cmd << '--indirect' if datastore['INDIRECT']
      cmd << "--domain #{datastore['DOMAIN']}" if datastore['DOMAIN']
      cmd << "--export #{datastore['EXPORT']}" if datastore['EXPORT']
      cmd << "--db #{datastore['DB_PATH']}" if datastore['DB_PATH']
  
      full_cmd = cmd.join(' ')
      print_status("Executing BloodBash: #{full_cmd}")
  
      # Execute the command and capture output
      output = `#{full_cmd} 2>&1`  # Capture stdout and stderr
      exit_code = $?.exitstatus
  
      if exit_code != 0
        print_error("BloodBash execution failed with exit code #{exit_code}")
        print_error("Output: #{output}")
        return
      end
  
      # Display and process output
      print_status("BloodBash analysis completed. Output:")
      print_line(output)
  
      # Parse and report key findings to Metasploit DB (basic example; enhance as needed)
      report_findings(output)
    end
  
    def report_findings(output)
      # Basic parsing: Look for critical findings and report them
      findings = output.scan(/(\[red\].*?\[\/red\])/m)  # Regex to extract red-highlighted critical findings
      findings.each do |finding|
        # Clean up Rich formatting for plain text
        clean_finding = finding.gsub(/\[[^\]]*\]/, '')  # Remove ANSI/Rich tags
        report_vuln(
          :host => datastore['RHOST'] || 'localhost',  # Use a placeholder or specify
          :name => 'BloodBash AD Vulnerability',
          :info => "Detected: #{clean_finding}",
          :refs => ['BloodHound', 'SharpHound']
        )
      end
  
      print_good("Reported #{findings.size} findings to Metasploit database.")
    end
  end