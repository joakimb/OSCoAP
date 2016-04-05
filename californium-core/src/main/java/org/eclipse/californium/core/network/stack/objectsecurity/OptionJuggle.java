package org.eclipse.californium.core.network.stack.objectsecurity;

import org.eclipse.californium.core.coap.Option;
import org.eclipse.californium.core.coap.OptionNumberRegistry;
import org.eclipse.californium.core.coap.OptionSet;

/**
 * Created by joakim on 05/04/16.
 */
public class OptionJuggle {

    public static OptionSet moveOptionsToOSPayload(OptionSet options) {
        ObjectSecurityOption osOpt = filterOSOption(options);
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

    public static ObjectSecurityOption filterOSOption(OptionSet options){
        if (options.hasOption(OptionNumberRegistry.OBJECT_SECURITY)) {
            for (Option o : options.asSortedList()) {
                if (o.getNumber() == OptionNumberRegistry.OBJECT_SECURITY) {
                    return (ObjectSecurityOption) o;
                }
            }
        }
        return null;
    }

}
