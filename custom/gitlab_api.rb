require "gitlab"

# Utility class to access the gitlab api

class GitlabApi

  # Finds the issue with same title and labels, and reate one if not exist
  def put_issue_if_not_exists(endpoint, token, project, title, description, label, assignee)
    #puts "endpoint #{endpoint}"
    #puts "token #{token}"
    #puts "project #{project}"
    #puts "title #{title}"
    #puts "description #{description}"
    #puts "label #{label}"
    #puts "assignee #{assignee}"
    #print "Issue: "+title
    Gitlab.endpoint = endpoint
    Gitlab.private_token = token
    issues = Gitlab.issues(project, { per_page: 40, state: "opened", labels: label })
    issues.each do |issue|
      #puts "issue: #{issue.id} #{issue.state} #{issue.title}"
      return "already submitted" if issue.title==title
    end
    Gitlab.create_issue(project, title, options = { description: description, labels: label, assignee_id: assignee })
    return "submitted"
  end

end