# frozen_string_literal: true

class PersonalizationSettingsController < ApplicationController
  ALLOWED_KEYS = [
    AccountConfig::FORM_COMPLETED_BUTTON_KEY,
    AccountConfig::SUBMITTER_INVITATION_EMAIL_KEY,
    AccountConfig::SUBMITTER_DOCUMENTS_COPY_EMAIL_KEY,
    AccountConfig::SUBMITTER_COMPLETED_EMAIL_KEY,
    AccountConfig::FORM_COMPLETED_MESSAGE_KEY,
    *(Docuseal.multitenant? ? [] : [AccountConfig::POLICY_LINKS_KEY])
  ].freeze

  InvalidKey = Class.new(StandardError)

  before_action :load_and_authorize_account_config, only: :create

  def show
    authorize!(:read, AccountConfig)
  end

  def create
    if @account_config.value.is_a?(Hash)
      @account_config.value = @account_config.value.reject do |_, v|
        v.blank? && v != false
      end
    end

    if @account_config.value != false && @account_config.value.blank?
      @account_config.destroy!
    else
      @account_config.save!
    end

    redirect_back(fallback_location: settings_personalization_path, notice: I18n.t('settings_have_been_saved'))
  end

  def logo
    authorize!(:update, current_account)

    if params[:logo].present?
      if params[:logo].content_type != 'image/png'
        return redirect_back(fallback_location: settings_personalization_path, 
                           alert: 'Only PNG files are allowed')
      end

      # Read the PNG content and attach it
      png_content = params[:logo].read
      blob = ActiveStorage::Blob.create_and_upload!(
        io: StringIO.new(png_content),
        filename: params[:logo].original_filename,
        content_type: 'image/png'
      )
      
      current_account.logo.attach(blob)
      notice = 'Logo has been updated successfully'
    end

    redirect_back(fallback_location: settings_personalization_path, notice: notice)
  end

  def delete_logo
    authorize!(:update, current_account)

    current_account.logo.purge if current_account.logo.attached?

    redirect_back(fallback_location: settings_personalization_path, 
                 notice: 'Logo has been removed successfully')
  end

  private

  def load_and_authorize_account_config
    @account_config =
      current_account.account_configs.find_or_initialize_by(key: account_config_params[:key])

    @account_config.assign_attributes(account_config_params)

    authorize!(:create, @account_config)

    raise InvalidKey unless ALLOWED_KEYS.include?(@account_config.key)

    @account_config
  end

  def account_config_params
    attrs = params.require(:account_config).permit!

    return attrs if attrs[:value].is_a?(String)

    attrs[:value]&.transform_values! do |value|
      if value.in?(%w[true false])
        value == 'true'
      else
        value
      end
    end

    attrs
  end
end
