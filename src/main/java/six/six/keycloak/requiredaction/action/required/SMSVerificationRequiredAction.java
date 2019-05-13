package six.six.keycloak.requiredaction.action.required;

import org.jboss.logging.Logger;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.*;
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
    private static final String MOBILE_NUMBER = "mobile_number";

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
                        Response challenge = context.form().createForm("sms-validation.ftl");
                        context.challenge(challenge);
                    } else {
                        Response challenge = context.form()
                                .setError("sms-auth.not.send")
                                .createForm("sms-validation-error.ftl");
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
                                .setError("sms-auth.not.mobile")
                                .createForm("sms-validation-error.ftl");
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
            Map<String, String> config = model.getConfig();

            MultivaluedMap<String, String> formData = context.getHttpRequest().getFormParameters();

            if(formData.containsKey(RESEND_CODE)) {
                requiredActionChallenge(context);
            } else if(formData.containsKey(UPDATE_MOBILE)) {
                UserModel user = context.getUser();
                String mobileNumber = MobileNumberHelper.getMobileNumber(user);

                Response challenge = context.form()
                        .setAttribute("phoneNumber", mobileNumber)
                        .createForm("sms-validation-mobile-number.ftl");
                context.challenge(challenge);
            } else if(formData.containsKey(MOBILE_NUMBER)) {
                String answer = (context.getHttpRequest().getDecodedFormParameters().getFirst("mobile_number"));
                if (answer != null && answer.length() > 0 && isPhoneNumberValid(answer)) {
                    logger.debug("Valid matching mobile numbers supplied, save credential ...");
                    List<String> mobileNumber = new ArrayList<>();
                    mobileNumber.add(answer);

                    UserModel user = context.getUser();
                    user.setAttribute(KeycloakSmsConstants.ATTR_MOBILE, mobileNumber);

                    requiredActionChallenge(context);
                } else {
                    logger.debug("The field wasn\'t complete or is an invalid number...");
                    Response challenge = context.form()
                            .setError("mobile_number.no.valid")
                            .createForm("sms-validation-mobile-number.ftl");
                    context.challenge(challenge);
                }
            } else {
                CODE_STATUS status = validateCode(context);
                Response challenge = null;
                switch (status) {
                    case EXPIRED:
                        challenge = context.form()
                                .setError("sms-auth.code.expired")
                                .createForm("sms-validation.ftl");
                        context.challenge(challenge);
                        break;

                    case INVALID:
                        challenge = context.form()
                                .setError("sms-auth.code.invalid")
                                .createForm("sms-validation.ftl");
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
