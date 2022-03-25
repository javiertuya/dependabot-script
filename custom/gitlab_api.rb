require "gitlab"

# Utility class to access the gitlab api

class GitlabApi

  # Finds the issue with same title and labels, and reate one if not exist
  def put_issue_if_not_exists(dry_run, endpoint, token, project, title, description, label, assignee)
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
      #Issue already submitted, issue reminder if needed
      return put_issue_reminder_if_older_than(dry_run, project, issue.iid, issue.updated_at, 14) if issue.title==title
    end

    #creates the issue, or message if dry_run
    return "not submitted as set by DRY_RUN" if dry_run
    Gitlab.create_issue(project, title, options = { description: description, labels: label, assignee_id: assignee })
    return "submitted"
  end

  def put_issue_reminder_if_older_than(dry_run, project_id, issue_id, updated_at, max_age)
    age = Date.today.mjd - Date.parse(updated_at).mjd + 1 # one day tolerance
    return "already submitted, last update #{age} days ago" if age<max_age
    return "reminder for #{age} days old issue not submitted as set by DRY_RUN" if dry_run
    Gitlab.create_issue_note(project_id, issue_id, "This is a **reminder** about this issue because it has not been updated for **#{age} days**")
    return "reminder for #{age} days old issue"
  end
end