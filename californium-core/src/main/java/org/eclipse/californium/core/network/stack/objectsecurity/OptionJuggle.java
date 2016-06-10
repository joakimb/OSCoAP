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
        boolean hasObserve = options.hasObserve();

        boolean hasUriHost = options.hasUriHost();
        boolean hasUriPort = options.hasUriPort();
        boolean hasProxyScheme = options.hasProxyScheme();

        int observe = 0;
        String proxyUri = null;
        String uriHost = null;
        int uriPort = 0;
        String proxyScheme = null;

        if (hasProxyUri) {
            proxyUri = options.getProxyUri();
            System.out.println("uri=: " + proxyUri);
        }
        if (hasObserve) {
            observe = options.getObserve();
        }
        if (hasUriHost) {
            uriHost = options.getUriHost();
        }
        if (hasUriPort) {
            uriPort = options.getUriPort();
        }
        if (hasProxyScheme) {
            proxyScheme = options.getProxyScheme();
        }
        options.clear();
        options.addOption(osOpt);
        if (hasProxyUri) {
            System.out.println("uncensored: " + proxyUri);
            proxyUri = proxyUri.replace("coap://", "");
            proxyUri = proxyUri.replace("coaps://", "");
            System.out.println("scheme stripped: " + proxyUri);
            int i = proxyUri.indexOf('/');
            if (i >= 0){
                proxyUri = proxyUri.substring(0,i);
            }
            proxyUri = "coap://" + proxyUri;

            options.setProxyUri(proxyUri);
        }
        if (hasObserve) {
            options.setObserve(observe);
        }
        if (hasUriHost) {
            options.setUriHost(uriHost);
        }
        if (hasUriPort) {
            options.setUriPort(uriPort);
        }
        if (hasProxyScheme) {
            options.setProxyScheme(proxyScheme);
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
