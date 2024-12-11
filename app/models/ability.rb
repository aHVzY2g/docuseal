# frozen_string_literal: true

class Ability
  include CanCan::Ability

  def initialize(user)
    return if user.blank?

    # Basic abilities for all authenticated users
    apply_base_abilities(user)

    case user.role
    when User::ADMIN_ROLE
      apply_admin_abilities
    when User::EDITOR_ROLE
      apply_editor_abilities(user)
    when User::MEMBER_ROLE
      apply_member_abilities(user)
    when User::AGENT_ROLE
      apply_agent_abilities(user)
    when User::VIEWER_ROLE
      apply_viewer_abilities(user)
    end
  end

  private

  def apply_base_abilities(user)
    # Basic read access to own account's users
    can :read, User, account_id: user.account_id
    # Users can manage their own profile
    can :manage, User, id: user.id
  end

  def apply_admin_abilities
    # Admin has full access to everything
    can :manage, :all
  end

  def apply_editor_abilities(user)
    # Full documents access
    can :manage, Template, account_id: user.account_id
    # Template folder permissions - can do everything including rename
    can :manage, TemplateFolder, account_id: user.account_id
    can :manage, Submission, account_id: user.account_id
    can :manage, Submitter, account_id: user.account_id
    
    # Can manage own configurations but not account settings
    can :manage, UserConfig, user_id: user.id
    
    # Cannot access account settings and users
    cannot :manage, Account
    cannot :manage, User
    cannot :manage, EncryptedConfig
    cannot :access, :settings
  end

  def apply_member_abilities(user)
    # Read access to all documents and templates
    can :read, Template, account_id: user.account_id
    can :read, Submission, account_id: user.account_id
    
    # Template folder permissions - can read and create but not rename
    can :read, TemplateFolder, account_id: user.account_id
    can :create, TemplateFolder, account_id: user.account_id
    cannot :update, TemplateFolder
    
    # Full access to own documents
    can :manage, Submission, account_id: user.account_id, author_id: user.id
    can :manage, Submitter, submission: { account_id: user.account_id, author_id: user.id }
    
    # Can send signature requests from any template
    can :create, Submission, account_id: user.account_id
    
    # Can clone any template
    can :clone, Template, account_id: user.account_id
    
    # Can manage own configurations
    can :manage, UserConfig, user_id: user.id
    
    # Cannot access account settings
    cannot :manage, Account
    cannot :manage, User
    cannot :manage, EncryptedConfig
    cannot :access, :settings
  end

  def apply_agent_abilities(user)
    # Read-only access to templates
    can :read, Template, account_id: user.account_id
    
    # Template folder permissions - read only
    can :read, TemplateFolder, account_id: user.account_id
    cannot :create, TemplateFolder
    cannot :update, TemplateFolder
    
    # Full access to own documents
    can :manage, Submission, account_id: user.account_id, author_id: user.id
    can :manage, Submitter, submission: { account_id: user.account_id, author_id: user.id }
    
    # Can send signature requests from templates
    can :create, Submission, account_id: user.account_id
    
    # Can manage own configurations
    can :manage, UserConfig, user_id: user.id
    
    # Cannot access account settings
    cannot :manage, Account
    cannot :manage, User
    cannot :manage, EncryptedConfig
    cannot :access, :settings
    
    # Cannot manage templates
    cannot :manage, Template
  end

  def apply_viewer_abilities(user)
    # Read-only access to documents
    can :read, Template, account_id: user.account_id
    can :read, Submission, account_id: user.account_id
    
    # Template folder permissions - read only
    can :read, TemplateFolder, account_id: user.account_id
    cannot :create, TemplateFolder
    cannot :update, TemplateFolder
    
    # Explicitly prevent all template and document creation/management
    cannot :create, Template # Prevents template creation and upload form display
    cannot :new, Template # Prevents access to new template form
    cannot :manage, Template
    
    # Prevent submission management
    cannot :create, Submission # Prevents signature requests
    cannot :manage, Submission
    cannot :manage, Submitter
    cannot :update, submission
    
    # Prevent settings access
    cannot :manage, UserConfig
    cannot :manage, EncryptedConfig
    cannot :manage, Account
    cannot :manage, User
    cannot :access, :settings
    
    # Prevent template operations
    cannot :clone, Template
  end
end
