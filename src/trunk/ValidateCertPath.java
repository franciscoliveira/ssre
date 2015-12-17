/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package trunk;

import java.io.File;
import java.io.FileInputStream;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertPathValidatorResult;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

/**
 * ValidateCertPath : validates an X.509 certification path
 *      using a PKIX CertPathValidator
 *
 * **/

public class ValidateCertPath {
    
    public Boolean validate(String trustAnchor, CertPath cp) throws Exception{
        PKIXParameters params = createParams(trustAnchor);
        try{
        CertPathValidator cpv = CertPathValidator.getInstance("PKIX");
        CertPathValidatorResult cpvr = cpv.validate(cp, params);
        System.out.println(cpvr);
        return true;
        }catch(CertPathValidatorException e){System.out.println("Certificate did not validate");return false;}
    }

    public static PKIXParameters createParams(String anchorFile) throws Exception {
        TrustAnchor anchor = new TrustAnchor(getCertFromFile(anchorFile), null);
        Set anchors = Collections.singleton(anchor);
        PKIXParameters params = new PKIXParameters(anchors);
        params.setRevocationEnabled(false);
        return params;
    }
       
    public static CertPath createPath(X509Certificate cert) throws Exception {
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
        List list = new ArrayList();
        list.add(cert);
    CertPath cp = cf.generateCertPath(list);
    return cp;
    }   
    
    /**
     * Get a DER or BASE64-encoded X.509 certificate from a file.
     *
     * @param certFilePath path to file containing DER or BASE64-encoded certificate
     * @return X509Certificate
     * @throws Exception on error
     */
    public static X509Certificate getCertFromFile(String certFilePath) throws Exception {
        X509Certificate cert = null;
        File certFile = new File(certFilePath);
        FileInputStream certFileInputStream = new FileInputStream(certFile);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        cert = (X509Certificate) cf.generateCertificate(certFileInputStream);
        return cert;
    }
}