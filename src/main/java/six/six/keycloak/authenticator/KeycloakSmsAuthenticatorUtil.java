package six.six.keycloak.authenticator;


import com.google.i18n.phonenumbers.NumberParseException;
import com.google.i18n.phonenumbers.PhoneNumberUtil;
import com.google.i18n.phonenumbers.Phonenumber.PhoneNumber;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.theme.Theme;
import org.keycloak.theme.ThemeProvider;
import six.six.gateway.Gateways;
import six.six.gateway.SMSService;
import six.six.gateway.aws.snsclient.SnsNotificationService;
import six.six.gateway.govuk.notify.NotifySMSService;
import six.six.gateway.lyrasms.LyraSMSService;
import six.six.keycloak.EnvSubstitutor;
import six.six.keycloak.KeycloakSmsConstants;

import java.io.IOException;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Random;

/**
 * Created by joris on 18/11/2016.
 */
public class KeycloakSmsAuthenticatorUtil {

    private static Logger logger = Logger.getLogger(KeycloakSmsAuthenticatorUtil.class);

    public static String getAttributeValue(UserModel user, String attributeName) {
        String result = null;
        List<String> values = user.getAttribute(attributeName);
        if (values != null && values.size() > 0) {
            result = values.get(0);
        }

        return result;
    }

    public static String getConfigString(Map<String, String> config, String configName) {
        return getConfigString(config, configName, null);
    }

    public static String getConfigString(Map<String, String> config, String configName, String defaultValue) {
        return config.getOrDefault(configName, defaultValue);
    }

    public static Long getConfigLong(Map<String, String> config, String configName) {
        return getConfigLong(config, configName, null);
    }

    public static Long getConfigLong(Map<String, String> config, String configName, Long defaultValue) {

        Long value = defaultValue;

        // Get value
        Object obj = config.get(configName);
        try {
            value = Long.valueOf((String) obj); // s --> ms
        } catch (NumberFormatException nfe) {
            logger.error("Can not convert " + obj + " to a number.");
        }

        return value;
    }

    public static Boolean getConfigBoolean(Map<String, String> config, String configName) {
        return getConfigBoolean(config, configName, true);
    }

    public static Boolean getConfigBoolean(Map<String, String> config, String configName, Boolean defaultValue) {

        Boolean value = defaultValue;

        // Get value
        String obj = config.get(configName);
        try {
            value = Boolean.valueOf(obj); // s --> ms
        } catch (NumberFormatException nfe) {
            logger.error("Can not convert " + obj + " to a boolean.");
        }

        return value;
    }

    public static String createMessage(String text, String code, String mobileNumber) {
        if (text != null) {
            text = text.replaceAll("%sms-code%", code);
            text = text.replaceAll("%phonenumber%", mobileNumber);
        }
        return text;
    }

    public static String setDefaultCountryCodeIfZero(String mobileNumber, String prefix, String condition) {

        if (prefix != null && condition != null && mobileNumber.startsWith(condition)) {
            mobileNumber = prefix + mobileNumber.substring(1);
        }
        return mobileNumber;
    }

    /**
     * Check mobile number normative strcuture
     *
     * @param mobileNumber
     * @return formatted mobile number
     */
    public static String checkMobileNumber(String mobileNumber) {

        PhoneNumberUtil phoneUtil = PhoneNumberUtil.getInstance();
        try {
            PhoneNumber phone = phoneUtil.parse(mobileNumber, null);
            mobileNumber = phoneUtil.format(phone,
                    PhoneNumberUtil.PhoneNumberFormat.E164);
        } catch (NumberParseException e) {
            logger.error("Invalid phone number " + mobileNumber, e);
        }

        return mobileNumber;
    }


    private static String getMessage(String key, RealmModel realm, KeycloakSession session, UserModel user) {
        String result = null;
        try {
            ThemeProvider themeProvider = session.getProvider(ThemeProvider.class, "extending");
            Theme currentTheme = themeProvider.getTheme(realm.getLoginTheme(), Theme.Type.LOGIN);
            Locale locale = session.getContext().resolveLocale(user);
            result = currentTheme.getMessages(locale).getProperty(key);
        } catch (IOException e) {
            logger.warn(key + "not found in messages");
        }
        return result;
    }


    public static boolean sendSmsCode(String mobileNumber, String code, RequiredActionContext context, Map<String, String> config) {
        return sendSmsCode(mobileNumber, code, config, context.getRealm(), context.getSession(), context.getUser());
    }

    public static boolean sendSmsCode(String mobileNumber, String code, AuthenticationFlowContext context, Map<String, String> config) {
        return sendSmsCode(mobileNumber, code, config, context.getRealm(), context.getSession(), context.getUser());
    }

    private static boolean sendSmsCode(String mobileNumber, String code, Map<String, String> config, RealmModel realm, KeycloakSession session, UserModel user) {
        // Send an SMS
        KeycloakSmsAuthenticatorUtil.logger.debug("Sending " + code + "  to mobileNumber " + mobileNumber);

        String smsUsr = EnvSubstitutor.envSubstitutor.replace(getConfigString(config, KeycloakSmsConstants.CONF_PRP_SMS_CLIENTTOKEN));
        String smsPwd = EnvSubstitutor.envSubstitutor.replace(getConfigString(config, KeycloakSmsConstants.CONF_PRP_SMS_CLIENTSECRET));
        String gateway = getConfigString(config, KeycloakSmsConstants.CONF_PRP_SMS_GATEWAY);

        // LyraSMS properties
        String endpoint = EnvSubstitutor.envSubstitutor.replace(getConfigString(config, KeycloakSmsConstants.CONF_PRP_SMS_GATEWAY_ENDPOINT));
        boolean isProxy = getConfigBoolean(config, KeycloakSmsConstants.PROXY_ENABLED);

        // GOV.UK Notify properties
        String notifyApiKey = System.getenv(KeycloakSmsConstants.NOTIFY_API_KEY);
        String notifyTemplate = System.getenv(KeycloakSmsConstants.NOTIFY_TEMPLATE_ID);

        // Create the SMS message body
        String template = getMessage(KeycloakSmsConstants.CONF_PRP_SMS_TEXT, realm, session, user);
        String smsText = createMessage(template, code, mobileNumber);

        boolean result;
        SMSService smsService;
        try {
            Gateways g = Gateways.valueOf(gateway);
            switch (g) {
                case LYRA_SMS:
                    smsService = new LyraSMSService(endpoint, isProxy);
                    break;
                case GOVUK_NOTIFY:
                    smsService = new NotifySMSService(notifyApiKey, notifyTemplate);
                    break;
                default:
                    smsService = new SnsNotificationService();
            }

            result = smsService.send(checkMobileNumber(setDefaultCountryCodeIfZero(mobileNumber, getMessage(KeycloakSmsConstants.MSG_MOBILE_PREFIX_DEFAULT, realm, session, user), getMessage(KeycloakSmsConstants.MSG_MOBILE_PREFIX_CONDITION, realm, session, user))), smsText, smsUsr, smsPwd);
            return result;
        } catch (Exception e) {
            logger.error("Fail to send SMS ", e);
            return false;
        }
    }

    public static String getSmsCode(long nrOfDigits) {
        if (nrOfDigits < 1) {
            throw new RuntimeException("Number of digits must be bigger than 0");
        }

        int addition = (int)Math.pow(10, nrOfDigits - 1);
        int seed = addition * 9;
        Random rand = new Random();
        int number = rand.nextInt(seed) + addition;
        return Integer.toString(number);
    }

    /**
     * This validation matches the registration flow's validation
     * https://github.com/UKGovernmentBEIS/beis-mspsds/blob/master/keycloak/providers/registration-form/src/main/java/uk/gov/beis/opss/keycloak/providers/RegistrationMobileNumber.java#L55
     */
    public static boolean isPhoneNumberValid(String phoneNumber) {
        String formattedPhoneNumber = convertInternationalPrefix(phoneNumber);

        String region;
        if (isPossibleNationalNumber(formattedPhoneNumber)) {
            region = "GB";
        } else if (isInternationalNumber(formattedPhoneNumber)) {
            region = null;
        } else {
            return false; // If the number cannot be interpreted as an international or possible UK phone number, do not attempt to validate it.
        }

        try {
            PhoneNumber parsedPhoneNumber = PhoneNumberUtil.getInstance().parse(formattedPhoneNumber, region);
            return PhoneNumberUtil.getInstance().isValidNumber(parsedPhoneNumber);
        } catch (NumberParseException e) {
            return false;
        }
    }

    private static String convertInternationalPrefix(String phoneNumber) {
        String trimmedPhoneNumber = phoneNumber.trim();
        if (trimmedPhoneNumber.startsWith("00")) {
            return trimmedPhoneNumber.replaceFirst("00", "+");
        }
        return trimmedPhoneNumber;
    }

    private static boolean isPossibleNationalNumber(String phoneNumber) {
        return phoneNumber.trim().startsWith("+44") || phoneNumber.trim().startsWith("07");
    }

    private static boolean isInternationalNumber(String phoneNumber) {
        return phoneNumber.trim().startsWith("+");
    }
}
