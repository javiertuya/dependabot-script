require_relative "vulnerability_fetcher"
require_relative "gitlab_api"

# Utility class to support a number of customizations on dependabot-script
# - dry run mode
# - ignore dependencies and versions
# - notifications on vulnerable dependencies
# This class is instantiated in generic-update-script so as the script is kept as most as possible similar to the original

class CustomUtil

  def initialize(package_manager, dependencies)
    @package_manager = package_manager
    @all_ignore = []
    unless ENV["IGNORE"].to_s.strip.empty?
      @all_ignore = ENV["IGNORE"].strip.split(';')
    end
    @all_vulnerabilities = get_all_vulnerabilities_for(dependencies)
    #Error if using deprecated env var
    unless ENV["IGNORE_VERSIONS"].to_s.strip.empty?
      puts "ERROR: IGNORE_VERSIONS is no longer used, all version exclusions must be included in the IGNORE environment variable"
      exit
    end
  end
  
  # Determines if dry run mode is active, overriding PR creation as
  # specified by the DRY_RUN environment variable (default is false)
  def dry_run?
    return !ENV["DRY_RUN"].to_s.strip.empty? && ENV["DRY_RUN"]=="true"
  end

  ##################################################
  # Management of ignore dependencies and versions #
  ##################################################

  # Determines if a dependency must be ignored as set by the IGNORE environment variable
  # Example: IGNORE="junit:junit; org.apache.httpcomponents:httpclient"  
  def ignore_dependencies_for(dep)
    @all_ignore.each do |ignore|
      return true if !ignore.include?("?") && match_dependency_name?(ignore, dep.name)
    end
    return false   
  end
  
  # Determines if the given versions of a dependency must be ignored as set by the IGNORE environment variable
  # Example: IGNORE="Microsoft.EntityFrameworkCore.Design? >=5: Microsoft.Data.SQLite? 5.*.*+6.*.*" 
  # Example: IGNORE="gitlab/gitlab-ce? >=14.6,<14.8
  def ignored_versions_for(dep)
    return ignored_versions_for_name(dep.name)
  end
  def ignored_versions_for_name(dep_name)
    @all_ignore.each do |ignore|
      dep_and_version = ignore.strip.split('?')
      return dep_and_version[1].strip.split('+') if dep_and_version.length()>1 && match_dependency_name?(dep_and_version[0].strip, dep_name)
    end
    return []
  end

  # Returns true if the specified dependency matches a dependency name
  # (specified dependency a wildcard at the end for approximate matches)
  def match_dependency_name?(dep_as_specified, dep_name)
    dep_as_specified = dep_as_specified.strip
    dep_name = dep_name.strip
    if dep_as_specified.end_with?("*") #approximate match
      return dep_name.start_with?(dep_as_specified[0..-2]) #remove last
    else
      return dep_as_specified == dep_name
    end
  end
  
  ##################################################
  # Management of vulnerable dependencies          #
  ##################################################

  #gets all vulnerabilities for the set of dependencies
  def get_all_vulnerabilities_for(dependencies)
    dep_names = []
    dependencies.each do |dep|
      dep_names.push(dep.name)
    end
    vulns = VulnerabilityFetcher.new(dep_names, @package_manager).fetch_advisories
    vulns = patch_fetched_vulnerabilities(vulns)
    return vulns
  end
  # Many problems found with determining vulnerable versions, eg: org.apache.logging.log4j:log4j-core and com.google.guava:guava
  # Problems due to:
  # - More than one vulnerability record -> patch: keeps only one (from graphql we get 2 records, here we keep the first)
  # - Vulnerability is specified as a range -> patch: keeps only upper limit (this will try to update to latest version en all cases, except if there are ignored versions)
  # - On org.apache.httpcomponents:httpclient there is a record for v5, but v5 does not exist (v5 is in a different package) -> patch: keeps the second instead of the first
  # - Ignoring major versions that have some vulnerability record, byt keep a lower version not vulnerable with previous vulnerabilities 
  #   reports a false positive issue -> patched in issue #1
  def patch_fetched_vulnerabilities(vulns)
    puts "All vulnerabilities:"
    vulns.each do |dep_name, vuln|
      if vuln.length()>0
        puts "  - Before patch: #{dep_name} #{vuln.to_json}"
        patch_remove_ignored_vulnerabilities(dep_name, vuln)
        if dep_name=="org.apache.httpcomponents:httpclient" && vuln.length()>1 && vuln[0]["vulnerable_versions".to_sym][0].start_with?(">= 5.0.0")
          #vuln=[{"patched_versions":["5.0.3"],"vulnerable_versions":[">= 5.0.0, < 5.0.3"]},{"patched_versions":["4.5.13"],"vulnerable_versions":["< 4.5.13"]}]
          vuln.delete_at(0) #remove first as v5 does not exist
        elsif vuln.length()>1
          vuln.delete_at(1) #keeps only first (provided that graphql retrieved two records)
        end
        if vuln[0]["vulnerable_versions".to_sym][0].split(",").length>1 # keeps only upper bound if a range specified
          vuln[0]["vulnerable_versions".to_sym][0] = vuln[0]["vulnerable_versions".to_sym][0].split(",")[1].strip
        end
        puts "    After patch:  #{dep_name} #{vuln.to_json}"
      end
    end
    return vulns
  end
  #Matches lower of ignored version >=X with lower bound of vulnerability >=Y
  #if equal, removes the vunerability as it affects to an ignored version (X,Y are major version numbers)
  #at the moment only consider first items, dirty, but works for me
  def patch_remove_ignored_vulnerabilities(dep_name, vuln)
    ignored = ignored_versions_for_name(dep_name)
    return vuln if ignored.length()==0 or vuln.length()==0
    ignoredArray = ignored[0].split(',')
    vulnArray = vuln[0]["vulnerable_versions".to_sym][0].split(',')
    ignoredBound = (ignoredArray[0].gsub(" ","") + ".0").split('.')[0]
    vulnBound = (vulnArray[0].gsub(" ","") + ".0").split('.')[0]
    if (ignoredBound == vulnBound && ignoredBound.start_with?(">="))
      puts "      Remove ignored vulnerability: matched ignored version: #{ignored[0].to_json} with vulnerability: #{vuln[0].to_json}"
      vuln.delete_at(0)
    end
  end

  # Gets the known vulnerabilities of a dependency in the required format to be passed to an update checker
  # Based on https://gist.github.com/BobbyMcWho/3ce09bde5abb674e61092efbe7390ffb with some adaptations
  # Tested with maven and nuget only
  def security_vulnerabilities_for(dep)
    security_vulnerabilities = []
    if @all_vulnerabilities.any?
      vulnerabilities = @all_vulnerabilities[dep.name]
      security_vulnerabilities = vulnerabilities.map do |vuln|
        Dependabot::SecurityAdvisory.new(
          dependency_name: dep.name,
          package_manager: @package_manager,
          vulnerable_versions: vuln[:vulnerable_versions],
          safe_versions: vuln[:patched_versions]
        )
      end
    end
    return security_vulnerabilities
  end

  # Determines if package to be updated has vulnerabilities                                                         
  # Uses a different checker than the used in the main script to set the security_advisories parameter.
  # This will let dependabot determine if there is any vulnerability
  def package_is_vulnerable?(dep, files, credentials, ignored_versions)
    if @package_manager!="docker" #docker does not report vulnerabilities
      checker_vuln = Dependabot::UpdateCheckers.for_package_manager(@package_manager).new(
        dependency: dep,
        dependency_files: files,
        credentials: credentials,
        ignored_versions: ignored_versions,
        security_advisories: security_vulnerabilities_for(dep),
        )
      #puts "  Checker.security_advisories #{checker_vuln.security_advisories}"
      #puts "  checker vulnerable? #{checker_vuln.vulnerable?}"
      #puts "  checker.lowest_resolvable_security_fix_version #{checker_vuln.lowest_resolvable_security_fix_version}"
      #puts "  checker.latest_version #{checker_vuln.latest_version}"
      #puts "  checker.lowest_security_fix_version #{checker_vuln.lowest_security_fix_version}"
      if checker_vuln.vulnerable?
        return true
      end 
    end
    return false
  end

  # Creates an issue for a dependency that is vulnerable but can not be updated (Gitlab only)
  def create_issue_for_vulnerable(source, dependency)
    title = "[SECURITY-UPDATE]: Bump "+dependency.name+" from "+dependency.version+" - Take action ASAP"
    description = "Dependency can not be updated to a more recent version, but **has known vulnerabilities**. This may be due to any of the following reasons:"+
    "\r\n- Dependency is obsolete and no longer maintained: Replace it with a different dependency"+
    "\r\n- The no vulnerable versions are excluded by dependabot: Contact your repository manager to update the exclusions"+
    "\r\n- There is no update available yet: Hold this issue and take the appropriate countermeasures until an update is available"+
    "\r\n- False positive: Submit an issue to https://github.com/javiertuya/dependabot-script"
    label = get_labels(true)
    assignee = ENV["PULL_REQUESTS_ASSIGNEE"] || ENV["GITLAB_ASSIGNEE_ID"]
    token=ENV["GITLAB_ACCESS_TOKEN"]
    print "  - Create issue: " + title
    if token.to_s.strip.empty?
      puts " - not submitted (no gitlab credentials available)"
    else
      api = GitlabApi.new
      ret = api.put_issue_if_not_exists(dry_run?, source.api_endpoint, token, source.repo, title, description, label, assignee)
      puts " - " + ret
    end
  end

  # Puts a reminder in old merge requests (including non-dependabot)
  def reminder_old_mrs(source)
    token=ENV["GITLAB_ACCESS_TOKEN"]
    api = GitlabApi.new
    api.remind_old_mrs(dry_run?, source.api_endpoint, token, source.repo)
  end

  # Default labels to be included in the PR:
  # - if dependency is not vulnerable gets nil to let dependabot set the default labels
  # - if dependency is vulnerable returns the label SECURITY-UPDATE label (must be created manually) plus the default labels
  def get_labels(package_is_vulnerable)
    return package_is_vulnerable ? ["SECURITY-UPDATE", "dependencies", get_language_label] : nil
  end

  # Additional prefix to be set in the commit title (nil if not vulnerable)
  def get_message_options(package_is_vulnerable)
    return { prefix: (package_is_vulnerable ? "[SECURITY-UPDATE]" : nil) }
  end

  #determines the label name for a given package manager to allow setting the same labels than dependabot defaults
  def get_language_label
    if @package_manager == "maven"
      return "java"
    elsif @package_manager == "nuget"
      return ".NET"
    elsif @package_manager == "pip"
      return "python"
    else
      return @package_manager
    end
  end
    
end  