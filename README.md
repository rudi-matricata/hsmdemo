# Using HSM with Java

### How the config file for the 'SunPKCS11' provider may look like:
```
# Give the HSM device a name
name = NitroKeyHSM

# Path to the PKCS#11 driver
library = C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll

# The HSM slot number
slotListIndex = 0
```


### Example client
```
public class HSMClient {

	public static void main(String[] args) throws URISyntaxException, GeneralSecurityException {
		
		System.out.println("Example 1 output: ");
		
		CloseableHttpClient client = HttpClientBuilder.create().build();
		
		URI signatureAddress = new URI("http", null, "localhost", 9001, "/signData", "data=hello", null);
		HttpGet httpGet = new HttpGet(signatureAddress);
		
		try (CloseableHttpResponse response = client.execute(httpGet)) {
			String base64EncodedSignatureString = response.getHeaders("Signature")[0].getValue();
			byte[] signatureData = Base64.getDecoder().decode(base64EncodedSignatureString);
			System.out.println("Signature: " + base64EncodedSignatureString);
			
			// read the public key from a file (exported from the HSM)
			RSAPublicKey publicKey = RSAPublicKeyUtils.getPublicKey("publickey.pem");
			
			Signature signature = Signature.getInstance("SHA256withRSA");
			signature.initVerify(publicKey);
			
			String incomingStringDataToBeVerified = IOUtils.readInputStreamToString(response.getEntity().getContent(), UTF_8);
			System.out.println("Data recieved: " + incomingStringDataToBeVerified);
			
			byte[] dataToBeVerified = incomingStringDataToBeVerified.getBytes(UTF_8);
			signature.update(dataToBeVerified);

			if(signature.verify(signatureData)) {
				System.out.println("Signature successfully verfied");
			} else {
				System.out.println("Signature verfification failed");
			}
	    } catch (IOException e) {
	    	System.out.println(e);
	    }
	}
	
}
```

### Some tools commands used
```
Generate keypair on the HSM:
pkcs11-tool (--module path to the opensc-pkcs11.dll library(for Windows)) -l --pin 648219 --keypairgen --key-type rsa:2048 --id 10 --label test_label

Export public key from the HSM:
pkcs15-tool --read-public-key keyid -o publickey.pem

```
