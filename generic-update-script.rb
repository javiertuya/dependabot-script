# This script is designed to loop through all dependencies in a GHE, GitLab or
# Azure DevOps project, creating PRs where necessary.

require "dependabot/file_fetchers"
require "dependabot/file_parsers"
require "dependabot/update_checkers"
require "dependabot/file_updaters"
require "dependabot/pull_request_creator"
require "dependabot/omnibus"
require "gitlab"
require_relative "vulnerability_fetcher"

credentials = [
  {
    "type" => "git_source",
    "host" => "github.com",
    "username" => "x-access-token",
    "password" => ENV["GITHUB_ACCESS_TOKEN"] # A GitHub access token with read access to public repos
  }
]

# Full name of the repo you want to create pull requests for.
repo_name = ENV["PROJECT_PATH"] # namespace/project

# Directory where the base dependency files are.
directory = ENV["DIRECTORY_PATH"] || "/"

# Branch to look at. Defaults to repo's default branch
branch = ENV["BRANCH"]

# Name of the package manager you'd like to do the update for. Options are:
# - bundler
# - pip (includes pipenv)
# - npm_and_yarn
# - maven
# - gradle
# - cargo
# - hex
# - composer
# - nuget
# - dep
# - go_modules
# - elm
# - submodules
# - docker
# - terraform
package_manager = ENV["PACKAGE_MANAGER"] || "bundler"

if ENV["GITHUB_ENTERPRISE_ACCESS_TOKEN"]
  credentials << {
    "type" => "git_source",
    "host" => ENV["GITHUB_ENTERPRISE_HOSTNAME"], # E.g., "ghe.mydomain.com",
    "username" => "x-access-token",
    "password" => ENV["GITHUB_ENTERPRISE_ACCESS_TOKEN"] # A GHE access token with API permission
  }

  source = Dependabot::Source.new(
    provider: "github",
    hostname: ENV["GITHUB_ENTERPRISE_HOSTNAME"],
    api_endpoint: "https://#{ENV['GITHUB_ENTERPRISE_HOSTNAME']}/api/v3/",
    repo: repo_name,
    directory: directory,
    branch: branch,
  )
elsif ENV["GITLAB_ACCESS_TOKEN"]
  gitlab_hostname = ENV["GITLAB_HOSTNAME"] || "gitlab.com"

  credentials << {
    "type" => "git_source",
    "host" => gitlab_hostname,
    "username" => "x-access-token",
    "password" => ENV["GITLAB_ACCESS_TOKEN"] # A GitLab access token with API permission
  }

  source = Dependabot::Source.new(
    provider: "gitlab",
    hostname: gitlab_hostname,
    api_endpoint: "https://#{gitlab_hostname}/api/v4",
    repo: repo_name,
    directory: directory,
    branch: branch,
  )
elsif ENV["AZURE_ACCESS_TOKEN"]
  azure_hostname = ENV["AZURE_HOSTNAME"] || "dev.azure.com"

  credentials << {
    "type" => "git_source",
    "host" => azure_hostname,
    "username" => "x-access-token",
    "password" => ENV["AZURE_ACCESS_TOKEN"]
  }

  source = Dependabot::Source.new(
    provider: "azure",
    hostname: azure_hostname,
    api_endpoint: "https://#{azure_hostname}/",
    repo: repo_name,
    directory: directory,
    branch: branch,
  )
elsif ENV["BITBUCKET_ACCESS_TOKEN"]
  bitbucket_hostname = ENV["BITBUCKET_HOSTNAME"] || "bitbucket.org"

  credentials << {
    "type" => "git_source",
    "host" => bitbucket_hostname,
    "username" => nil,
    "token" => ENV["BITBUCKET_ACCESS_TOKEN"]
  }

  source = Dependabot::Source.new(
    provider: "bitbucket",
    hostname: bitbucket_hostname,
    api_endpoint: ENV["BITBUCKET_API_URL"] || "https://api.bitbucket.org/2.0/",
    repo: repo_name,
    directory: directory,
    branch: nil,
  )
elsif ENV["BITBUCKET_APP_USERNAME"] && ENV["BITBUCKET_APP_PASSWORD"]
  bitbucket_hostname = ENV["BITBUCKET_HOSTNAME"] || "bitbucket.org"

  credentials << {
    "type" => "git_source",
    "host" => bitbucket_hostname,
    "username" => ENV["BITBUCKET_APP_USERNAME"],
    "password" => ENV["BITBUCKET_APP_PASSWORD"]
  }

  source = Dependabot::Source.new(
    provider: "bitbucket",
    hostname: bitbucket_hostname,
    api_endpoint: ENV["BITBUCKET_API_URL"] || "https://api.bitbucket.org/2.0/",
    repo: repo_name,
    directory: directory,
    branch: branch,
  )
else
  source = Dependabot::Source.new(
    provider: "github",
    repo: repo_name,
    directory: directory,
    branch: branch,
  )
end

#returns true if the specified dependency matches a dependency name
#(specified dependency use * at the end for approximate matches)
def match_dependency_name?(dep_as_specified, dep_name)
  if dep_as_specified.end_with?("*") #approximate match
    return dep_name.start_with?(dep_as_specified[0..-2]) #remove last
  else
    return dep_as_specified == dep_name
  end
end

#######################################################################
# Semicolon separated list of dependencies to ignore.                 #
# IGNORE="junit:junit; org.apache.httpcomponents:httpclient"          #
#######################################################################
def ignore_dependencies_for(dep)
  unless ENV["IGNORE"].to_s.strip.empty?
    ignore_dependencies = ENV["IGNORE"].strip.split(';')
    ignore_dependencies.each do |dep_to_ignore|
      return true if match_dependency_name?(dep_to_ignore.strip, dep.name)
    end
  end
  return false   
end

###################################################################################################
# Semicolon separated list of dependencies ov version specifications to ignore.                   #
# Each version specification is in the form `dependency?version-1|version-2|...`                  #
# Example:                                                                                        #
# IGNORE_VERSIONS="Microsoft.EntityFrameworkCore.Design?>=5: Microsoft.Data.SQLite?5.*.*+6.*.*"   #
###################################################################################################

def ignored_versions_for(dep)
  unless ENV["IGNORE_VERSIONS"].to_s.strip.empty?
    ignore_versions = ENV["IGNORE_VERSIONS"].strip.split(';')
    ignore_versions.each do |dep_and_version|
      dep_and_version_array=dep_and_version.strip.split('?')
      return dep_and_version_array[1].strip.split('+') if match_dependency_name?(dep_and_version_array[0].strip, dep.name)
    end
  end
  return []
end

###########################################################################################################
# Gets the known vulnerabilities of a dependency in the required format to be passed to an update checker #
# Based on https://gist.github.com/BobbyMcWho/3ce09bde5abb674e61092efbe7390ffb with some adaptations      #
# Tested with maven and nuget only                                                                        #
###########################################################################################################

def security_vulnerabilities_for(dep, package_manager)
  vulnerabilities = VulnerabilityFetcher.new([dep.name], package_manager).fetch_advisories
  if vulnerabilities[:package].length()>0
    puts "  Vulnerability info: #{vulnerabilities.to_json}"
  end
  security_vulnerabilities = []
  if vulnerabilities.any?
    security_vulnerabilities = vulnerabilities[:package].map do |vuln|
      Dependabot::SecurityAdvisory.new(
        dependency_name: dep.name,
        package_manager: package_manager,
        #When exist both lower and upper limit, it was unable to get the correct behaviour. Keeps only last (upper) if more than one
        #Examples: org.apache.logging.log4j:log4j-core and com.google.guava:guava report vulnerability when there is not
        vulnerable_versions: [vuln[:vulnerable_versions][vuln[:vulnerable_versions].length()-1]],
        safe_versions: vuln[:patched_versions]
      )
    end
  end
  return security_vulnerabilities
end

def language_label_for(package_manager)
  if package_manager == "maven"
    return "java"
  elsif package_manager == "nuget"
    return ".NET"
  else
    return package_manager
  end
end


##############################
# DRY_RUN will not create PR #
##############################
dry_run = !ENV["DRY_RUN"].to_s.strip.empty? && ENV["DRY_RUN"]=="true"
puts "Dry run configuration: #{dry_run}"

##############################
# Fetch the dependency files #
##############################
puts "Fetching #{package_manager} dependency files for #{repo_name}"
fetcher = Dependabot::FileFetchers.for_package_manager(package_manager).new(
  source: source,
  credentials: credentials,
)

files = fetcher.files
commit = fetcher.commit

##############################
# Parse the dependency files #
##############################
puts "Parsing dependencies information"
parser = Dependabot::FileParsers.for_package_manager(package_manager).new(
  dependency_files: files,
  source: source,
  credentials: credentials,
)

dependencies = parser.parse

dependencies.select(&:top_level?).each do |dep|
  next if dep.name=="org.eclipse.m2e:lifecycle-mapping" #skip as this is not a true dependency
  print "Check dependency: #{dep.name} (#{dep.version})"

  #########################################
  # Get update details for the dependency #
  #########################################
  ignored_versions = ignored_versions_for(dep)
  checker = Dependabot::UpdateCheckers.for_package_manager(package_manager).new(
    dependency: dep,
    dependency_files: files,
    credentials: credentials,
    ignored_versions: ignored_versions,
  )
  puts ignored_versions.length()==0 ? "" : " - With ignored versions: #{ignored_versions}"

  next if checker.up_to_date?

  ##############################################################
  # Determines if package to be update has vulnerabilities     #                                                              
  # Uses a different checker the security_advisories parameter #
  # to let dependabot determine if there is any vulnerability  #
  ##############################################################
  package_is_vulnerable=false
  if package_manager!="docker" #docker does not report vulnerabilities
    checker_vuln = Dependabot::UpdateCheckers.for_package_manager(package_manager).new(
      dependency: dep,
      dependency_files: files,
      credentials: credentials,
      ignored_versions: ignored_versions,
      security_advisories: security_vulnerabilities_for(dep, package_manager),
      )
    #puts "  Checker.security_advisories #{checker_vuln.security_advisories}"
    #puts "  checker vulnerable? #{checker_vuln.vulnerable?}"
    #puts "  checker.lowest_resolvable_security_fix_version #{checker_vuln.lowest_resolvable_security_fix_version}"
    #puts "  checker.latest_version #{checker_vuln.latest_version}"
    #puts "  checker.lowest_security_fix_version #{checker_vuln.lowest_security_fix_version}"
    if checker_vuln.vulnerable?
      package_is_vulnerable = true
    end 
  end

  #ignore this dependency if was included in the IGNORE environment variable
  if ignore_dependencies_for(dep)
    print "  - Ignoring #{dep.name} (from #{dep.version})…"
    puts " excluded as set by IGNORE environment variable"
    next
  end

  requirements_to_unlock =
    if !checker.requirements_unlocked_or_can_be?
      if checker.can_update?(requirements_to_unlock: :none) then :none
      else :update_not_possible
      end
    elsif checker.can_update?(requirements_to_unlock: :own) then :own
    elsif checker.can_update?(requirements_to_unlock: :all) then :all
    else :update_not_possible
    end

  next if requirements_to_unlock == :update_not_possible

  updated_deps = checker.updated_dependencies(
    requirements_to_unlock: requirements_to_unlock
  )

  #####################################
  # Generate updated dependency files #
  #####################################
  print "  - Updating #{dep.name} (from #{dep.version})…"
  updater = Dependabot::FileUpdaters.for_package_manager(package_manager).new(
    dependencies: updated_deps,
    dependency_files: files,
    credentials: credentials,
  )

  updated_files = updater.updated_dependency_files
  print "(to #{updater.dependencies[0].version})"
  if package_is_vulnerable
    print " [SECURITY-UPDATE]"
  end

  # skip PR submission if dry_run
  if dry_run
    puts " not submitted as set by DRY_RUN environment variable"
    next
  end

  ########################################
  # Create a pull request for the update #
  ########################################
  assignee = (ENV["PULL_REQUESTS_ASSIGNEE"] || ENV["GITLAB_ASSIGNEE_ID"])&.to_i
  assignees = assignee ? [assignee] : assignee
  # default labels if no security updates (use nil because if empty array all labels will be removed)
  # or SECURITY-UPDATE label (must be created manually) plus the default labels
  custom_labels = package_is_vulnerable ? ["SECURITY-UPDATE", "dependencies",language_label_for(package_manager)] : nil 
  pr_creator = Dependabot::PullRequestCreator.new(
    source: source,
    base_commit: commit,
    dependencies: updated_deps,
    files: updated_files,
    credentials: credentials,
    assignees: assignees,
    author_details: { name: "Dependabot", email: "no-reply@github.com" },
    label_language: true,
    custom_labels: custom_labels,
    commit_message_options: { prefix: (package_is_vulnerable ? "[SECURITY-UPDATE]" : nil) }
  )
  pull_request = pr_creator.create
  puts " submitted"

  next unless pull_request

  # Enable GitLab "merge when pipeline succeeds" feature.
  # Merge requests created and successfully tested will be merge automatically.
  if ENV["GITLAB_AUTO_MERGE"]
    g = Gitlab.client(
      endpoint: source.api_endpoint,
      private_token: ENV["GITLAB_ACCESS_TOKEN"]
    )
    g.accept_merge_request(
      source.repo,
      pull_request.iid,
      merge_when_pipeline_succeeds: true,
      should_remove_source_branch: true
    )
  end
end

puts "Done"
