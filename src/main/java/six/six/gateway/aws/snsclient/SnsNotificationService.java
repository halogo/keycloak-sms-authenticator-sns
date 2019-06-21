package six.six.gateway.aws.snsclient;

import com.amazonaws.services.sns.model.MessageAttributeValue;
import com.amazonaws.services.sns.model.PublishRequest;
import com.amazonaws.services.sns.model.PublishResult;
import six.six.gateway.SMSService;

import java.util.HashMap;
import java.util.Map;

/**
 * Created by nickpack on 09/08/2017.
 */
public class SnsNotificationService implements SMSService {

    //TODO Implement proxy

    public boolean send(String phoneNumber, String message, String clientToken, String clientSecret) {
        Map<String, MessageAttributeValue> smsAttributes = new HashMap<>();
        smsAttributes.put("AWS.SNS.SMS.SenderID", new MessageAttributeValue()
                .withStringValue("HaloGo")
                .withDataType("String"));

        smsAttributes.put("AWS.SNS.SMS.SMSType", new MessageAttributeValue()
                .withStringValue("Transactional")
                .withDataType("String"));

        PublishResult result = SnsClientFactory.getSnsClient(clientToken, clientSecret).publish(new PublishRequest()
                .withMessage(message)
                .withPhoneNumber(phoneNumber)
                .withMessageAttributes(smsAttributes));

        return (result.getMessageId()!=null);
    }
}
