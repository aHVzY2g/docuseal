# frozen_string_literal: true

class ApplicationController < ActionController::Base
  BROWSER_LOCALE_REGEXP = /\A\w{2}(?:-\w{2})?/

  include ActiveStorage::SetCurrent
  include Pagy::Backend

  check_authorization unless: :devise_controller?

  around_action :with_locale
  before_action :authenticate_via_remote_user_header
  before_action :sign_in_for_demo, if: -> { Docuseal.demo? }
  before_action :maybe_redirect_to_setup, unless: :signed_in?
  before_action :authenticate_user!, unless: :devise_controller?

  helper_method :button_title,
                :current_account,
                :form_link_host,
                :svg_icon

  impersonates :user, with: ->(uuid) { User.find_by(uuid:) }

  rescue_from Pagy::OverflowError do
    redirect_to request.path
  end

  rescue_from RateLimit::LimitApproached do |e|
    Rollbar.error(e) if defined?(Rollbar)

    redirect_to request.referer, alert: 'Too many requests', status: :too_many_requests
  end

  if Rails.env.production?
    rescue_from CanCan::AccessDenied do |e|
      Rollbar.warning(e) if defined?(Rollbar)

      redirect_to root_path, alert: e.message
    end
  end

  def default_url_options
    if request.domain == 'docuseal.com'
      return { host: 'docuseal.com', protocol: ENV['FORCE_SSL'].present? ? 'https' : 'http' }
    end

    Docuseal.default_url_options
  end

  def impersonate_user(user)
    raise ArgumentError unless user
    raise Pretender::Error unless true_user

    @impersonated_user = user

    request.session[:impersonated_user_id] = user.uuid
  end

  private

  def authenticate_via_remote_user_header
    return if signed_in?

    remote_user = request.headers['X-Remote-User']
    return unless remote_user.present?

    user = User.active.find_by(email: remote_user)

    if user.nil? && ENV['AUTOCREATE_USERS'].to_s.downcase == 'true'
      # Create new user if autocreate is enabled
      random_password = SecureRandom.hex(32)
      
      # Find or create default account
      account = Account.first_or_create!(name: 'Default Account')
      
      user = User.new(
        email: remote_user,
        password: random_password,
        password_confirmation: random_password,
        account: account
      )
      
      # Set name if provided in headers
      if (remote_name = request.headers['X-Remote-Name'].presence)
        name_parts = remote_name.split
        if name_parts.size >= 2
          user.first_name = name_parts[0...-1].join(' ')
          user.last_name = name_parts.last
        end
      end

      # Set default role or map from groups if provided
      user.role = User::MEMBER_ROLE
      user.save!
    end

    return unless user

    if (remote_name = request.headers['X-Remote-Name'].presence)
      name_parts = remote_name.split
      if name_parts.size >= 2
        # If there are 3 or more parts, treat all but the last as first name
        user.first_name = name_parts[0...-1].join(' ')
        user.last_name = name_parts.last
        user.save
      end
    end

    remote_groups = request.headers['X-Remote-Group'].to_s.split(',')
    if remote_groups.present?
      group_role_mapping = {
        ENV.fetch('GROUP_ADMIN', 'group-admin') => User::ADMIN_ROLE,
        ENV.fetch('GROUP_EDITOR', 'group-editor') => User::EDITOR_ROLE,
        ENV.fetch('GROUP_VIEWER', 'group-viewer') => User::VIEWER_ROLE,
        ENV.fetch('GROUP_MEMBER', 'group-member') => User::MEMBER_ROLE,
        ENV.fetch('GROUP_AGENT', 'group-agent') => User::AGENT_ROLE
      }

      remote_groups.each do |group|
        if (role = group_role_mapping[group])
          user.update(role: role)
          break
        end
      end
    end

    sign_in(user)
  end

  def with_locale(&)
    return yield unless current_account

    locale   = params[:lang].presence if Rails.env.development?
    locale ||= current_account.locale

    I18n.with_locale(locale, &)
  end

  def with_browser_locale(&)
    return yield if I18n.locale != :'en-US' && I18n.locale != :en

    locale   = params[:lang].presence
    locale ||= request.env['HTTP_ACCEPT_LANGUAGE'].to_s[BROWSER_LOCALE_REGEXP].to_s

    locale =
      if locale.starts_with?('en-') && locale != 'en-US'
        'en-GB'
      else
        locale.split('-').first.presence || 'en-GB'
      end

    locale = 'en-GB' unless I18n.locale_available?(locale)

    I18n.with_locale(locale, &)
  end

  def sign_in_for_demo
    sign_in(User.active.order('random()').take) unless signed_in?
  end

  def current_account
    current_user&.account
  end

  def maybe_redirect_to_setup
    redirect_to setup_index_path unless User.exists?
  end

  def button_title(title: I18n.t('submit'), disabled_with: I18n.t('submitting'), title_class: '', icon: nil,
                   icon_disabled: nil)
    render_to_string(partial: 'shared/button_title',
                     locals: { title:, disabled_with:, title_class:, icon:, icon_disabled: })
  end

  def svg_icon(icon_name, class: '')
    render_to_string(partial: "icons/#{icon_name}", locals: { class: })
  end

  def form_link_host
    Docuseal.default_url_options[:host]
  end

  def maybe_redirect_com
    return if request.domain != 'docuseal.co'

    redirect_to request.url.gsub('.co/', '.com/'), allow_other_host: true, status: :moved_permanently
  end
end
