package org.eclipse.californium.core.network.stack.objectsecurity;

import org.eclipse.californium.core.coap.Option;
import org.eclipse.californium.core.coap.OptionNumberRegistry;
import org.eclipse.californium.core.coap.OptionSet;

import java.util.List;

/**
 * Created by joakim on 05/04/16.
 */
public class OptionJuggle {

    public static OptionSet moveOptionsToOSPayload(OptionSet options, ObjectSecurityOption osOpt) {

        boolean hasProxyUri = options.hasProxyUri();
        String proxyUri = null;
        if (hasProxyUri) {
            proxyUri = options.getProxyUri();
            options.removeProxyUri();
        }
        boolean hasMaxAge = options.hasMaxAge();
        if (hasMaxAge) {
            options.removeMaxAge();
        }
        options.clear();
        options.addOption(osOpt);
        if (hasProxyUri) {
            options.setProxyUri(proxyUri);
        }
        if (hasMaxAge) {
            options.setMaxAge(0);
        }
        return options;
    }

    public static OptionSet readOptionsFromOSPayload(byte[] content){
        List<Option> optionList = OSSerializer.readConfidentialOptions(content);
        OptionSet optionSet = new OptionSet();
        for (Option option : optionList) {
            optionSet.addOption(option);
        }
        return optionSet;
    }

    public static Option filterOSOption(OptionSet options){
        if (options.hasOption(OptionNumberRegistry.OBJECT_SECURITY)) {
            for (Option o : options.asSortedList()) {
                if (o.getNumber() == OptionNumberRegistry.OBJECT_SECURITY) {
                    return o;
                }
            }
        }
        return null;
    }


}
