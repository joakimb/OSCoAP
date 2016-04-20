package org.eclipse.californium.core.network.stack.objectsecurity;

import org.eclipse.californium.core.coap.Option;
import org.eclipse.californium.core.coap.OptionNumberRegistry;
import org.eclipse.californium.core.coap.OptionSet;

import java.util.List;

/**
 * Created by joakim on 05/04/16.
 */
public class OptionJuggle {

    public static OptionSet clearOptionsPresentInOSPayload(OptionSet options, Option osOpt) {

        boolean hasProxyUri = options.hasProxyUri();
        boolean hasObserve = options.hasProxyUri();
        int observe = 0;
        String proxyUri = null;
        if (hasProxyUri) {
            proxyUri = options.getProxyUri();
        }
        if (hasObserve) {
            observe = options.getObserve();
        }
        options.clear();
        options.addOption(osOpt);
        if (hasProxyUri) {
            options.setProxyUri(proxyUri);
        }
        if (hasObserve) {
            options.setObserve(observe);
        }
        options.setMaxAge(0);
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
