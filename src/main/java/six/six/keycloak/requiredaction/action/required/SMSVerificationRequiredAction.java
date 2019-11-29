package six.six.keycloak.requiredaction.action.required;

import org.jboss.logging.Logger;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.*;
import org.keycloak.models.utils.FormMessage;
import six.six.keycloak.KeycloakSmsConstants;
import six.six.keycloak.MobileNumberHelper;
import six.six.keycloak.authenticator.KeycloakSmsAuthenticatorUtil;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static six.six.keycloak.authenticator.KeycloakSmsAuthenticatorUtil.isPhoneNumberValid;

public class SMSVerificationRequiredAction implements RequiredActionProvider {
    private static Logger logger = Logger.getLogger(SMSVerificationRequiredAction.class);
    static final String PROVIDER_ID = "sms_verification";
    private static final String RESEND_CODE = "resend";
    private static final String UPDATE_MOBILE = "update_mobile";

    private static final String FIELD_SMS_CODE = "smsCode";

    private static final String SMS_VALIDATION_FTL = "sms-validation.ftl";
    private static final String SMS_VaLIDATION_ERROR_FTL = "sms-validation-error.ftl";
    private static final String SMS_VALIDATION_MOBILE_NUMBER_FTL = "sms-validation-mobile-number.ftl";

    private enum CODE_STATUS {
        VALID,
        INVALID,
        EXPIRED
    }

    @Override
    public void evaluateTriggers(RequiredActionContext requiredActionContext) {
        logger.debug("evaluateTriggers called ...");
    }

    @Override
    public void requiredActionChallenge(RequiredActionContext context) {
        logger.debug("requiredActionChallenge called ...");
        RequiredActionProviderModel model = getRequiredActionProviderModel(context.getRealm());

        if (model != null && model.getConfig() != null) {
            Map<String, String> config = model.getConfig();

            UserModel user = context.getUser();

            boolean onlyForVerification = KeycloakSmsAuthenticatorUtil.getConfigBoolean(config, KeycloakSmsConstants.MOBILE_VERIFICATION_ENABLED, false);

            String mobileNumber = getMobileNumber(user);
            String mobileNumberVerified = getMobileNumberVerified(user);

            if (!onlyForVerification || isOnlyForVerificationMode(onlyForVerification, mobileNumber, mobileNumberVerified)) {
                if (mobileNumber != null) {
                    // The mobile number is configured --> send an SMS
                    long nrOfDigits = KeycloakSmsAuthenticatorUtil.getConfigLong(config, KeycloakSmsConstants.CONF_PRP_SMS_CODE_LENGTH, 8L);
                    logger.debug("Using nrOfDigits " + nrOfDigits);


                    long ttl = KeycloakSmsAuthenticatorUtil.getConfigLong(config, KeycloakSmsConstants.CONF_PRP_SMS_CODE_TTL, 10 * 60L); // 10 minutes in s

                    logger.debug("Using ttl " + ttl + " (s)");

                    String code = KeycloakSmsAuthenticatorUtil.getSmsCode(nrOfDigits);

                    storeSMSCode(context, code, new Date().getTime() + (ttl * 1000)); // s --> ms
                    if (KeycloakSmsAuthenticatorUtil.sendSmsCode(mobileNumber, code, context, config)) {
                        Response challenge = context.form()
//                                .setInfo(code)
                                .createForm(SMS_VALIDATION_FTL);
                        context.challenge(challenge);
                    } else {
                        Response challenge = context.form()
                                .setError(Messages.SMS_AUTH_NOT_SEND)
                                .createForm(SMS_VaLIDATION_ERROR_FTL);
                        context.challenge(challenge);
                    }
                } else {
                    boolean isAskingFor = KeycloakSmsAuthenticatorUtil.getConfigBoolean(config, KeycloakSmsConstants.MOBILE_ASKFOR_ENABLED);
                    if (isAskingFor) {
                        //Enable access and ask for mobilenumber
                        user.addRequiredAction(KeycloakSmsMobilenumberRequiredAction.PROVIDER_ID);
                        context.success();
                    } else {
                        // The mobile number is NOT configured --> complain
                        Response challenge = context.form()
                                .setError(Messages.SMS_AUTH_NOT_MOBILE)
                                .createForm(SMS_VaLIDATION_ERROR_FTL);
                        context.challenge(challenge);
                    }
                }
            } else {
                logger.debug("Skip SMS code because onlyForVerification " + onlyForVerification + " or  mobileNumber==mobileNumberVerified");
                context.success();

            }
        }
    }

    @Override
    public void processAction(RequiredActionContext context) {
        logger.debug("action called ... context = " + context);
        RequiredActionProviderModel model = getRequiredActionProviderModel(context.getRealm());

        if (model != null && model.getConfig() != null) {
            List<FormMessage> errors = new ArrayList<>();
            Map<String, String> config = model.getConfig();

            MultivaluedMap<String, String> formData = context.getHttpRequest().getFormParameters();

            if(formData.containsKey(RESEND_CODE)) {
                context.form().setInfo(Messages.SMS_AUTH_SEND);
                requiredActionChallenge(context);
            } else if(formData.containsKey(UPDATE_MOBILE)) {
                UserModel user = context.getUser();
                String mobileNumber = MobileNumberHelper.getMobileNumber(user);

                Response challenge = context.form()
                        .setAttribute(KeycloakSmsConstants.ATTR_MOBILE, mobileNumber)
                        .createForm(SMS_VALIDATION_MOBILE_NUMBER_FTL);
                context.challenge(challenge);
            } else if(formData.containsKey(KeycloakSmsConstants.ATTR_MOBILE)) {
                String answer = (context.getHttpRequest().getDecodedFormParameters().getFirst(KeycloakSmsConstants.ATTR_MOBILE));
                if (answer != null && answer.length() > 0 && isPhoneNumberValid(answer)) {
                    logger.debug("Valid matching mobile numbers supplied, save credential ...");
                    List<String> mobileNumber = new ArrayList<>();
                    mobileNumber.add(answer);

                    UserModel user = context.getUser();
                    user.setAttribute(KeycloakSmsConstants.ATTR_MOBILE, mobileNumber);

                    requiredActionChallenge(context);
                } else {
                    logger.debug("The field wasn\'t complete or is an invalid number...");
                    errors.add(new FormMessage(KeycloakSmsConstants.ATTR_MOBILE, Messages.MOBILE_NUMBER_NO_VALID));
                    Response challenge = context.form()
                            .setErrors(errors)
                            .setAttribute(KeycloakSmsConstants.ATTR_MOBILE, answer)
                            .createForm(SMS_VALIDATION_MOBILE_NUMBER_FTL);
                    context.challenge(challenge);
                }
            } else {
                CODE_STATUS status = validateCode(context);
                Response challenge = null;
                switch (status) {
                    case EXPIRED:
                        errors.add(new FormMessage(FIELD_SMS_CODE, Messages.SMS_AUTH_CODE_EXPIRED));
                        challenge = context.form()
                                .setErrors(errors)
                                .setFormData(formData)
                                .createForm(SMS_VALIDATION_FTL);
                        context.challenge(challenge);
                        break;

                    case INVALID:
                        errors.add(new FormMessage(FIELD_SMS_CODE, Messages.SMS_AUTH_CODE_INVALID));
                        challenge = context.form()
                                .setErrors(errors)
                                .setFormData(formData)
                                .createForm(SMS_VALIDATION_FTL);
                        context.challenge(challenge);
                        break;

                    case VALID:
                        context.success();
                        updateVerifiedMobilenumber(context, config);
                        break;
                }
            }
        }
    }

    @Override
    public void close() {

    }

    /**
     * If necessary update verified mobilenumber
     *
     * @param context
     */
    private void updateVerifiedMobilenumber(RequiredActionContext context, Map<String, String> config) {
        UserModel user = context.getUser();
        boolean onlyForVerification = KeycloakSmsAuthenticatorUtil.getConfigBoolean(config, KeycloakSmsConstants.MOBILE_VERIFICATION_ENABLED);

        if (onlyForVerification) {
            //Only verification mode
            List<String> mobileNumberCreds = user.getAttribute(KeycloakSmsConstants.ATTR_MOBILE);
            if (mobileNumberCreds != null && !mobileNumberCreds.isEmpty()) {
                user.setAttribute(KeycloakSmsConstants.ATTR_MOBILE_VERIFIED, mobileNumberCreds);
            }
        }
    }

    // Store the code + expiration time in a UserCredential. Keycloak will persist these in the DB.
    // When the code is validated on another node (in a clustered environment) the other nodes have access to it's values too.
    private void storeSMSCode(RequiredActionContext context, String code, Long expiringAt) {
        UserCredentialModel credentials = new UserCredentialModel();
        credentials.setType(KeycloakSmsConstants.USR_CRED_MDL_SMS_CODE);
        credentials.setValue(code);

        context.getSession().userCredentialManager().updateCredential(context.getRealm(), context.getUser(), credentials);

        credentials.setType(KeycloakSmsConstants.USR_CRED_MDL_SMS_EXP_TIME);
        credentials.setValue((expiringAt).toString());
        context.getSession().userCredentialManager().updateCredential(context.getRealm(), context.getUser(), credentials);
    }


    protected CODE_STATUS validateCode(RequiredActionContext context) {
        CODE_STATUS result = CODE_STATUS.INVALID;

        logger.debug("validateCode called ... ");
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String enteredCode = formData.getFirst(KeycloakSmsConstants.ANSW_SMS_CODE);
        KeycloakSession session = context.getSession();

        List codeCreds = session.userCredentialManager().getStoredCredentialsByType(context.getRealm(), context.getUser(), KeycloakSmsConstants.USR_CRED_MDL_SMS_CODE);

        CredentialModel expectedCode = (CredentialModel) codeCreds.get(0);

        logger.debug("Expected code = " + expectedCode + "    entered code = " + enteredCode);

        if (expectedCode != null) {
            result = enteredCode.equals(expectedCode.getValue()) ? CODE_STATUS.VALID : CODE_STATUS.INVALID;
        }
        logger.debug("result : " + result);
        return result;
    }

    private boolean isOnlyForVerificationMode(boolean onlyForVerification, String mobileNumber, String mobileNumberVerified) {
        return (mobileNumber == null || onlyForVerification && !mobileNumber.equals(mobileNumberVerified));
    }

    private String getMobileNumber(UserModel user) {
        return MobileNumberHelper.getMobileNumber(user);
    }

    private String getMobileNumberVerified(UserModel user) {
        List<String> mobileNumberVerifieds = user.getAttribute(KeycloakSmsConstants.ATTR_MOBILE_VERIFIED);

        String mobileNumberVerified = null;
        if (mobileNumberVerifieds != null && !mobileNumberVerifieds.isEmpty()) {
            mobileNumberVerified = mobileNumberVerifieds.get(0);
        }
        return mobileNumberVerified;
    }

    private RequiredActionProviderModel getRequiredActionProviderModel(RealmModel realm) {
        for (RequiredActionProviderModel model : realm.getRequiredActionProviders()) {
            if (model.getAlias().equals(PROVIDER_ID)) {
                return model;
            }
        }

        return null;
    }
}
