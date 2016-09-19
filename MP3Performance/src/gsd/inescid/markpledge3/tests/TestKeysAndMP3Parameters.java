package gsd.inescid.markpledge3.tests;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

import gsd.inescid.crypto.ElGamalKeyFactory;
import gsd.inescid.crypto.ElGamalKeyPair;
import gsd.inescid.crypto.ElGamalKeyParameters;
import gsd.inescid.crypto.ElGamalPrivateKey;
import gsd.inescid.crypto.ElGamalPublicKey;
import gsd.inescid.markpledge3.MP3Parameters;

/**
 * This class provides methods to create ElGamal keys and MP3 parameters for testing purposes 
 * 
 * @author Rui Joaquim
 *
 */
public class TestKeysAndMP3Parameters {

	/** definition of the test key sizes **/
	// any change in this array implies a change in the method getStaticKeysAndMP3Parameters
	public static final int[][] TEST_KEY_SIZES = {// p ,  q
												   {64,  16},
												  {256,  64},
												  {512, 128},
												 {1024, 160},
												 {1024, 512},
												 {2048, 256} 
												};
	
	/**
	 * This method generates new ElGamal keys and MP3 parameters for the requested key sizes.
	 * @param keySizes the key size generation parameters
	 * @return an Object[] containing in each entry another Object[] with tree elements. The first 
	 * 		   element is the an ElGamalKeyPair; the second is a MP3Parameters with the 
	 * 		   BASE_VOTE_GENERATOR set to the key parameter g; and the third element are another 
	 * 		   MP3Parameters with a BASE_VOTE_GENERATOR different from the key parameter g.  
	 * @throws GeneralSecurityException if an error occurs in the generation process
	 */
	public static Object[][] generateNewKeysAndMP3Parameters(int[][] keySizes) throws GeneralSecurityException
	{
		SecureRandom r = new SecureRandom();
		String hashFunction = "SHA-256";
		ElGamalKeyParameters keyParam;
		ElGamalKeyPair keyPair;
		MP3Parameters mp3ParamSameGenerator, mp3ParamDifferentGenerator;
		
		Object[][] result = new Object[keySizes.length][];
	
		for(int i=0; i<keySizes.length; i++)
		{
			System.out.println("Generate key (p=" + TestKeysAndMP3Parameters.TEST_KEY_SIZES[i][0] +
					" q=" + TestKeysAndMP3Parameters.TEST_KEY_SIZES[i][1] + ")");
			
			keyParam  = new ElGamalKeyParameters(keySizes[i][0], keySizes[i][1], r, hashFunction);
			keyPair = ElGamalKeyFactory.createKeyPair(keyParam, r);
			mp3ParamSameGenerator = new MP3Parameters(keyPair.publicKey, keyPair.publicKey.g);
			mp3ParamDifferentGenerator = new MP3Parameters(keyPair.publicKey, 
					keyParam.getQOrderGenerator(keyParam.GENERATOR_INDEX+1));
			result[i] = new Object[]{keyPair,mp3ParamSameGenerator, mp3ParamDifferentGenerator};
			
			
			System.out.println("p: " + keyParam.p);
			System.out.println("q: " + keyParam.q);
			System.out.println("g: " + keyParam.g);
			System.out.println("kpub: " + keyPair.publicKey.h);
			BigInteger correctKpri = keyPair.privateKey.q.subtract(keyPair.privateKey.kpri);
			System.out.println("kpri: " + correctKpri);
			System.out.println("newGen: " + mp3ParamDifferentGenerator.BASE_VOTE_GENERATOR);
			
		}
		System.out.println("End of key generation");
		return result;
	}
	
			
	/**
	 * This method returns default static keys and MP3 parameters for the test keys sizes defined in the testKeySizes array. 
	 * @return an Object[] containing in each entry another Object[] with tree elements. The first 
	 * 		   element is the an ElGamalKeyPair; the second is a MP3Parameters with the 
	 * 		   BASE_VOTE_GENERATOR set to the key parameter g; and the third element are another 
	 * 		   MP3Parameters with a BASE_VOTE_GENERATOR different from the key parameter g.  
	 */
	public static Object[][] getStaticKeysAndMP3Parameters()
	{
		Object[][] result = new Object[TEST_KEY_SIZES.length][];
				
		result[0] = getStaticKeyP64G16();
		result[1] = getStaticKeyP256G64();
		result[2] = getStaticKeyP512G128();
		result[3] = getStaticKeyP1024G160();
		result[4] = getStaticKeyP2048G256();
		
		return result;
	}
	
	
	public static Object[] getStaticKeyP64G16()
	{
		ElGamalKeyParameters keyParameters; 
		ElGamalKeyPair keyPair;
		ElGamalPublicKey kpub;
		ElGamalPrivateKey kpri;
		MP3Parameters mp3ParamSameGenerator, mp3ParamDifferentGenerator;
		
		// p=64, q=16
		keyParameters = new ElGamalKeyParameters(
				new BigInteger("13837456570030819931"),
				new BigInteger("37019"),
				new BigInteger("12977221436981235315"));
	
		kpub = new ElGamalPublicKey(keyParameters,
				new BigInteger("3295523328044581023"));
	
		kpri = new ElGamalPrivateKey(keyParameters, new BigInteger("15857"));
	
		keyPair = new ElGamalKeyPair(kpub,kpri);
		mp3ParamSameGenerator = new MP3Parameters(keyPair.publicKey, keyPair.publicKey.g);
		mp3ParamDifferentGenerator = new MP3Parameters(keyPair.publicKey, 
				new BigInteger("408604428481721380"));
				
		return new Object[]{keyPair, mp3ParamSameGenerator, mp3ParamDifferentGenerator};
	}
	
	public static Object[] getStaticKeyP256G64()
	{
		ElGamalKeyParameters keyParameters; 
		ElGamalKeyPair keyPair;
		ElGamalPublicKey kpub;
		ElGamalPrivateKey kpri;
		MP3Parameters mp3ParamSameGenerator, mp3ParamDifferentGenerator;
		
		// p=256, q=64
		keyParameters = new ElGamalKeyParameters(
				new BigInteger("96509198243102796671880446802674469738718626049369117378023372848809843424647"),
				new BigInteger("9343454630408743073"),
				new BigInteger("1277521942415144182268691974932248538305429695828420578600404193489247113907"));
	
		kpub = new ElGamalPublicKey(keyParameters,
				new BigInteger("70716499088905278137866323685115627936414801464957261891346856480745220250170"));
	
		kpri = new ElGamalPrivateKey(keyParameters, new BigInteger("6951385531051507626"));
	
		keyPair = new ElGamalKeyPair(kpub,kpri);
		mp3ParamSameGenerator = new MP3Parameters(keyPair.publicKey, keyPair.publicKey.g);
		mp3ParamDifferentGenerator = new MP3Parameters(keyPair.publicKey, 
				new BigInteger("93937115936726946073999317970387641971994444515450480815542595701395627242527"));
	
				
		return new Object[]{keyPair, mp3ParamSameGenerator, mp3ParamDifferentGenerator};
	}
	
	public static Object[] getStaticKeyP512G128()
	{
		ElGamalKeyParameters keyParameters; 
		ElGamalKeyPair keyPair;
		ElGamalPublicKey kpub;
		ElGamalPrivateKey kpri;
		MP3Parameters mp3ParamSameGenerator, mp3ParamDifferentGenerator;
		
		// p=512, q=128
		keyParameters = new ElGamalKeyParameters(
				new BigInteger("8629062891067744184507022975662720378987473752990041787426291778605006743440995053806742448202855063320062101315540380750052591949644217479560721344478301"),
				new BigInteger("203171359722151877094721833199876607953"),
				new BigInteger("731113271782455786855822967753784344089103656793175692035250918928725753910790831430296535934107082040249272467144445005678295067622863511610517929368936"));
	
		kpub = new ElGamalPublicKey(keyParameters,
				new BigInteger("6676587245753767563913553972652208701923594844999906330382882820117390653405816592851206456726951137081624873981578162353822652328336355484011953780143879"));
	
		kpri = new ElGamalPrivateKey(keyParameters, new BigInteger("102931345831267247007754429951583826223"));
	
		keyPair = new ElGamalKeyPair(kpub,kpri);
		mp3ParamSameGenerator = new MP3Parameters(keyPair.publicKey, keyPair.publicKey.g);
		mp3ParamDifferentGenerator = new MP3Parameters(keyPair.publicKey, 
				new BigInteger("6996557188551014524187421388904142268178180223284134373616909244965852257356517592651482565495579186440808368192877410806178672834041737716626148973328867"));
					
		return new Object[]{keyPair, mp3ParamSameGenerator, mp3ParamDifferentGenerator};
	}
	
	public static Object[] getStaticKeyP1024G160()
	{
		ElGamalKeyParameters keyParameters; 
		ElGamalKeyPair keyPair;
		ElGamalPublicKey kpub;
		ElGamalPrivateKey kpri;
		MP3Parameters mp3ParamSameGenerator, mp3ParamDifferentGenerator;
		
		// p=1024, q=160
		keyParameters = new ElGamalKeyParameters(
				new BigInteger("130470968870528286672118143586041482832296937499955584891293930333642826100644641879704474969857755740174180260610863165369657635692984831930650808561759011819635010422895169804620908044467103375841580738520834946432658680149507181588222556910347296332900498450662754998416277255895542975772237915528385346661"),
				new BigInteger("730811166162110738948406901157474182798190119909"),
				new BigInteger("129729638897114263941225905289118065684824146093111372979453772142750568454464201927561593750438322467110495720795025323109746235168017685738749195858539379923076203366351224924186897451385903639672127800510157917819764574337372688597525806115257730267586218804304437564832525503501309541362721271193381757306"));
	
		kpub = new ElGamalPublicKey(keyParameters,
				new BigInteger("45767025888726386070108488564559440928599020324038738842453361133212926525336202096215878399514082747753885141063694439073197599837531588683558290924745678479886469616679191634577428419188052048458492539185624120833287555549952509917151284365869374971202428545754517940506832759567681482102895874841470343840"));
	
		kpri = new ElGamalPrivateKey(keyParameters, new BigInteger("394052556985592161199286759434965382703342345265"));
	
		keyPair = new ElGamalKeyPair(kpub,kpri);
		mp3ParamSameGenerator = new MP3Parameters(keyPair.publicKey, keyPair.publicKey.g);
		mp3ParamDifferentGenerator = new MP3Parameters(keyPair.publicKey, 
				new BigInteger("70401807425781495909966245405585007513541499599581515975362401472479518851979481812350882806415426057389128933449605597814560473495674550734084383741780626768743423355675941618808607929631051960018198773858260515477418899128040171740746551506852902486387008166266403245632597929046466152465071597113410210983"));
				
		return new Object[]{keyPair, mp3ParamSameGenerator, mp3ParamDifferentGenerator};
	}
	
	public static Object[] getStaticKeyP1024G512()
	{
		ElGamalKeyParameters keyParameters; 
		ElGamalKeyPair keyPair;
		ElGamalPublicKey kpub;
		ElGamalPrivateKey kpri;
		MP3Parameters mp3ParamSameGenerator, mp3ParamDifferentGenerator;
		
		// p=1024, q=512
		keyParameters = new ElGamalKeyParameters(
				new BigInteger("103556533855391617895735726608468730967847021408753974500991156615483205946421314539856850259885738397031074754379307647751246273587813355588807667744110363808352481018018719447656183359950668842356739853163835675549778694172672412403218355981339051612875335783469474453201511560260623120581676804408062963979"),
				new BigInteger("6703903964971298549787012499102923063739682910296196688861780721860882015036849757230662548869512066440609395477578634573873007470365783428635431615448703"),
				new BigInteger("4570432885706930601665625098706103556796261512303505277567326539687551816982289561726696968046828625484614530953862582426198423277429124781860566535662405044238474981938801363220918456351926244505514217458278330180600087081782036644439999180728299781326112031208840155853867469163772416998290805018961671014"));
	
		kpub = new ElGamalPublicKey(keyParameters,
				new BigInteger("50754639945331482909074566426182365574330567357741866752265411991196794461797837201366654302737933291736153869445688025357872172750419710185434896636610808347906485011804108577368563691544878513555899044559678719914134601516707325493896886274818986678921217313437545386035541041710719212811838560690475767377"));
	
		kpri = new ElGamalPrivateKey(keyParameters, new BigInteger("3812577254728305089739575357365020744955111833324354764523528562806820043542181505839467810454439044942450375658452503466828108698030694412079512285979394"));
	
		keyPair = new ElGamalKeyPair(kpub,kpri);
		mp3ParamSameGenerator = new MP3Parameters(keyPair.publicKey, keyPair.publicKey.g);
		mp3ParamDifferentGenerator = new MP3Parameters(keyPair.publicKey, 
				new BigInteger("11765401153366302947468846743729534580547843760777664125140988309190351268596813022660222895234584479059189020750298682580937009187081133398601599666891183551650820669853189991031088858076130054603270114625236874496191474405759118094101054890164717825130532307699000994324995388323506048478607506815874902972"));
				
		return new Object[]{keyPair, mp3ParamSameGenerator, mp3ParamDifferentGenerator};
	}
	
	
	public static Object[] getStaticKeyP2048G256()
	{
		ElGamalKeyParameters keyParameters; 
		ElGamalKeyPair keyPair;
		ElGamalPublicKey kpub;
		ElGamalPrivateKey kpri;
		MP3Parameters mp3ParamSameGenerator, mp3ParamDifferentGenerator;
		
		// p=2048, q=256 
		keyParameters = new ElGamalKeyParameters(
				new BigInteger("16352257667237795452492417876250074222750809651743189869241571854684121692239011921645405611213746550509969450351759057036537793013254302670316235466565160350050580677900551687327929225683651085726093331617060756077509286020436102285394710033225008646732184093540913404131679344310784021875576071628850880893451571981373921365507065646673348635988911097305420113796370556288349509306800407396409668370456278367354457813028770810805975019879735176561279203794800976255625391231041383405820731614486050021434444539899485092706740553523709074499265401852181809297292843964205937744768915315643840020397757205147728125261"),
				new BigInteger("108491933133315956354565649988568834360551714282059802822579040980758710858887"),
				new BigInteger("12310163142778325766446866142217294368872634893843537343041925025207627932956954434401281008561927472042855640532026554784476174321685647098087180770307341395179926129804122498182000139195028345498759220230644631576122471039947929467474585808316917626504859232715010582767449244237440223570148452716825108934591844287059404066155479711625113863773124514048311709396034699140937252639439472175943541961690804581942685647564575633337245525146710443859641937049318649847731741002708557556315441652194116259120736894920850652002640685598657404380311344149827392447478400229074392886579663030695765269161851881235521977724"));
	
		kpub = new ElGamalPublicKey(keyParameters,
				new BigInteger("6729719337571521934494018561616102299825003702340846300190387748095878034193046038910362348675863739379689476280881108966857184364068193176141996794624332663580825207350036058004481485738155424286454788356516270266635870091370944149614552127398710213598309987035799033329184664740866601593303229868278112900203965387241928113705117323297735869908528109609291037427016837540495306160791798859496258275348898459874918230123114407688873750102725584124303424902486309885396055873660100900009549098090429336744915835706367142812965624427336358777706052537128479645448444474791022836780991073389968765820001976764947543532"));
	
		kpri = new ElGamalPrivateKey(keyParameters, new BigInteger("78150287017636137646772971806795770228557708921095281135887768719376440780638"));
	
		keyPair = new ElGamalKeyPair(kpub,kpri);
		mp3ParamSameGenerator = new MP3Parameters(keyPair.publicKey, keyPair.publicKey.g);
		mp3ParamDifferentGenerator = new MP3Parameters(keyPair.publicKey, 
				new BigInteger("11712746286782309101659824100987267072018400791187768739156139556265840061205471889091851269148699394303251042212766865915219057972578952575599281915990854716128726616734884040813688475686112378457590357175117844824789724006129147781777798683717913711486592617047967679663310402127593914367552822095918219347262680396629043533686405658914094643072038229069547851128690031359289210331806115334484283705688502931255963198868094371298605023055758107251026925094438621699169343135915941749363916768627758392429954414512444939871371687366700187999619681680633811998989975811483709549998199155204432806272222176238315560132"));
		
		return new Object[]{keyPair, mp3ParamSameGenerator, mp3ParamDifferentGenerator};
	}
	
	public static void main(String args[]) throws GeneralSecurityException
	{
		generateNewKeysAndMP3Parameters(TEST_KEY_SIZES);
	}
}
