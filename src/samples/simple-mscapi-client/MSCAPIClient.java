import java.io.IOException;
import java.net.MalformedURLException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import javax.naming.ServiceUnavailableException;

import com.microsoft.aad.adal4j.MSCAPIAuthenticationContext;
import com.microsoft.aad.adal4j.AuthenticationResult;
import com.microsoft.aad.adal4j.MSCAPIAsymmetricKeyCredential;


public class MSCAPIClient {

	static String authority = "https://login.microsoftonline.com"; // Address of the authority to issue token
	static String tenant = "<YOUR TENANT ID>" ; // AAD Tenant identifier
	static String applicationId = "<YOUR APPLICATION IDENTIFIER>";  // Application id for AAD federated application
	
	// Identifier of the target resource that is the recipient of the requested token.
	// example - "https://vault.azure.net/" - if using to authnticate Azure key vault
	static String resource = "<YOUR TARGET RESOURCE>";  
	static String thumbprint = "<YOUR CLIENT CERTIFICATE THUMBPRINT>"; // Thumbprint of the client certificate being used to authenticate to AAD
	static String keyAlias = "<YOUR KEY ALIAS>";  // Alias of the private key in the windows keystore

	static KeyStore store;
	
	
	public static void main(String[] args) throws Exception {

		AuthenticationResult result = GetAccessToken();
		System.out.println("Access Token - " + result.getAccessToken());
            	System.out.println("Refresh Token - " + result.getRefreshToken());
            	System.out.println("ID Token - " + result.getIdToken());
			
	}
	
	/** Returns and AuthenticationResult from an authentication attempt 
	 * against Azure Active Directory
	 * @return an AuthenticationResult object that can be use to authenticate 
	 * to application federated with Azure Active Directory. 
	 * @throws Exception
	 */
	public static  AuthenticationResult GetAccessToken()
			throws Exception {
			
		store = getKeystore("Windows-MY");
		X509Certificate cert = FindCertificateByThumbprint(thumbprint);

		String Password = "";
		PrivateKey key = (PrivateKey)store.getKey(keyAlias, Password.toCharArray());

		String authorization = GetAuthorization(authority, tenant);
		

		MSCAPIAsymmetricKeyCredential cred = MSCAPIAsymmetricKeyCredential.create(applicationId, key, cert);
        MSCAPIAuthenticationContext context = null;
        AuthenticationResult result = null;
        ExecutorService service = null;
        try{
        service = Executors.newFixedThreadPool(1);
        context = new MSCAPIAuthenticationContext(authorization, true, service);
        Future<AuthenticationResult> future = context.acquireToken(resource, cred, null);
        result = future.get();    
        } finally {
        service.shutdown();
        }
        
        if (result == null) {
        	throw new ServiceUnavailableException(
        			"authentication result was null");
        }
        
        return result;
	}
	

	/**
	 * Returns a string object with the address of the authority to issue token 
	 * for the AAD Tenant
	 * @param authority
	 * @param tenant
	 * @return
	 */
	public static String GetAuthorization(String authority, String tenant)
	{
		StringBuilder sb = new StringBuilder();
		sb.append(authority)
		.append("/")
		.append(tenant)
		.append("/oauth2/authorize");
		return sb.toString();
	}
	
	
	/**
	 * Returns a Keystore object that created from the private key stored in
	 * the windows keystore and accessed using the sunMSCAPI provider.
	 * 
	 * @param storename - the windows keystore be accessed(Usually "Windows-MY").  
	 * "Windows-MY" represent private store of the user the application is running as. <b>Make sure the private key is deployed under the windows keystore for this user</b>
	 * @return a windows keystore object.
	 * @throws KeyStoreException
	 * @throws NoSuchProviderException
	 */
	public static KeyStore getKeystore(String storename) throws KeyStoreException, NoSuchProviderException{
	
			return KeyStore.getInstance(storename,"SunMSCAPI");

	}
	
	// Helper Methods to locate the certificate by thumbprint.  
	// This is done to help .NET developers transition to Java easier 
	// as accessing X509 certificate by thumbprint is a standard practice in .NET 
	
	public static X509Certificate FindCertificateByThumbprint(String findValue){
		
		Map<String, X509Certificate> X509CertMap = LoadStore();
		return X509CertMap.get(findValue);
		
	}
	
	public static Map<String, X509Certificate> LoadStore()
	{
		Map<String, X509Certificate> X509CertMap = new HashMap<String, X509Certificate>();
		try {
			try {
				store.load(null);
					
				Enumeration<String> alias;
				
				alias = store.aliases();
				
				while( alias.hasMoreElements())
				{
					String certAlias = alias.nextElement();
					X509Certificate cert = (X509Certificate)store.getCertificate(certAlias);
					String thumbprint = getThumbPrint(cert);
					X509CertMap.put(thumbprint, cert);		
				}
				
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (CertificateException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return X509CertMap;		
	}
	
   
	public static String getThumbPrint(X509Certificate cert) 
            throws NoSuchAlgorithmException, CertificateEncodingException {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            byte[] der = cert.getEncoded();
            md.update(der);
            byte[] digest = md.digest();
            return hexify(digest);

        }

        public static String hexify (byte bytes[]) {

            char[] hexDigits = {'0', '1', '2', '3', '4', '5', '6', '7', 
                    '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

            StringBuffer buf = new StringBuffer(bytes.length * 2);

            for (int i = 0; i < bytes.length; ++i) {
                buf.append(hexDigits[(bytes[i] & 0xf0) >> 4]);
                buf.append(hexDigits[bytes[i] & 0x0f]);
            }

            return buf.toString();
        }
	
	
}
