# frozen_string_literal: true

class SubmissionsArchivedController < ApplicationController
  load_and_authorize_resource :submission, parent: false
  before_action :check_viewer_role, only: %i[new create edit update destroy]

  def index
    @submissions = @submissions.joins(:template)
    @submissions = @submissions.where.not(archived_at: nil)
                               .or(@submissions.where.not(templates: { archived_at: nil }))
                               .preload(:created_by_user, template: :author)

    @submissions = @submissions.preload(:template_accesses) unless current_user.role.in?(%w[admin superadmin])

    @submissions = Submissions.search(@submissions, params[:q], search_template: true)
    @submissions = Submissions::Filter.call(@submissions, current_user, params)

    @submissions = if params[:completed_at_from].present? || params[:completed_at_to].present?
                     @submissions.order(Submitter.arel_table[:completed_at].maximum.desc)
                   else
                     @submissions.order(id: :desc)
                   end

    @pagy, @submissions = pagy(@submissions.preload(submitters: :start_form_submission_events))
  end
end
