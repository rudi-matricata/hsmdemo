package security.talks.hsm.hsmdemo;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Provider.Service;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Base64.Encoder;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HSMDemoController {

	private static final String DEMO_KEY_LABEL = "security_talks";

	@Autowired
	private HttpServletResponse httpServletResponse;
	
	private static final String KEYSTORE_TYPE = "PKCS11";
	private static final String HSM_PIN_ENV_KEY = "HSM_PIN";
	private static final String HSM_CONFIG_FILENAME = "hsm-config.cfg";

	private static final Provider PROVIDER = Security.getProvider("SunPKCS11").configure(HSM_CONFIG_FILENAME);
	
	private KeyPairGenerator kpg;
	private KeyStore hsmKeyStore;
	
	private Encoder encoder;
	
	public HSMDemoController() throws NoSuchAlgorithmException, CertificateException, IOException, KeyStoreException {
		this.hsmKeyStore = KeyStore.getInstance(KEYSTORE_TYPE, PROVIDER);
		
		this.kpg = KeyPairGenerator.getInstance("RSA", PROVIDER);
		this.kpg.initialize(2048);
		
		this.encoder = Base64.getEncoder();
	}
	
	private void login() throws NoSuchAlgorithmException, CertificateException, IOException {
		// You should login before doing anything with the HSM
		// Here i get my password from the environment (i set it there for the sake of the demo) but you can store it in more secure way
		this.hsmKeyStore.load(null, System.getenv(HSM_PIN_ENV_KEY).toCharArray());
	}
	
	/**
	 * Generates RSA keypair in the HSM 
	 * @throws NoSuchAlgorithmException 
	 * @throws IOException 
	 * @throws CertificateException 
	 */
	@GetMapping("/generateKeypair")
	public String generateKeypair() throws NoSuchAlgorithmException, CertificateException, IOException {
		login();
		PublicKey publicKey = kpg.generateKeyPair().getPublic();
		return new PublicKeyDTO(publicKey).toString();
	}
	
	/**
	 * List all services (type of service and algorithm that can be used) for the given provider (the HSM in this case)
	 * 
	 * @return List of services
	 */
	@GetMapping("/listProviderServices")
	public Map<String, List<String>> listProviderServices() {
		Set<Service> services =  PROVIDER.getServices();
		Map<String, List<String>> servicesMap = new HashMap<>();
		
		for(Service s : services) {
			servicesMap.computeIfAbsent(s.getType(), k -> new ArrayList<>()).add(s.getAlgorithm());
		}
		
		return servicesMap;
	}
	
	/**
	 * Signs data with the private key manually generated on the HSM and sets the signature calculated in a header
	 * 
	 * @param data to be signed
	 * 
	 * @return The data (plus hardcoded suffix) sent
	 * 
	 * @throws UnrecoverableKeyException
	 * @throws KeyStoreException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws SignatureException
	 * @throws IOException 
	 * @throws CertificateException 
	 */
	@GetMapping("/signData")
	public ResponseEntity<String> signData(@RequestParam(value = "data", required = true) String data) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, CertificateException, IOException {
		login();
		PrivateKey privateKey = (PrivateKey) hsmKeyStore.getKey(DEMO_KEY_LABEL, new char[0]);
		
		Signature signature = Signature.getInstance("SHA256withRSA", PROVIDER);
		signature.initSign(privateKey, new SecureRandom());
		
		String fullDataToBeSigned = (data + " signed from server");
		byte[] dataBytes = fullDataToBeSigned.getBytes(UTF_8);
		signature.update(dataBytes);
		
		byte[] signatureBytes = signature.sign();
		httpServletResponse.setHeader("Signature", encoder.encodeToString(signatureBytes));
		
		return ResponseEntity.ok(fullDataToBeSigned);
	}
	
	/**
	 * List all the keys (associated to a certificate) in the KeyStore
	 * 
	 * @return List of keys in the HSM
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws IOException
	 * @throws KeyStoreException
	 */
	@GetMapping("/listEntries")
	public List<String> listEntries() throws NoSuchAlgorithmException, CertificateException, IOException, KeyStoreException {
		login();
		
		Enumeration<String> entriesIterator = this.hsmKeyStore.aliases();
		
		List<String> entriesList = new ArrayList<>();
		while(entriesIterator.hasMoreElements()) {
			entriesList.add(entriesIterator.nextElement());
		}
		return entriesList;
	}
	
	@GetMapping("/messageDigest")
	public String calculateMD(@RequestParam(value = "data", required = true) String data) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA-256", PROVIDER);
		return encoder.encodeToString(md.digest(data.getBytes(UTF_8)));
	}
	
	private class PublicKeyDTO {
		private String keyMaterial;
		private PublicKey pk;
		
		PublicKeyDTO(PublicKey pk) {
			this.pk = pk;
			this.keyMaterial = Base64.getEncoder().encodeToString(pk.getEncoded());
		}
		
		@Override
		public String toString() {
			return "public key: " + this.keyMaterial + "\n" + pk.toString();
		}
	}
}




