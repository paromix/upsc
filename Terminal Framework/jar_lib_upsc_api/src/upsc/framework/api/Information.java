package upsc.framework.api;

/**
 * The public class of Information about UPSC API.
 */
public class Information {
	private final String UPSC_API_VERSION = "1.0";
	private String COMM_MODULE_INFO;

	/**
	 * Get Information about UPSC API.
	 * @return UPSC API Version.
	 */
	public String getString(){
		return "upsc.framework.api ver"+UPSC_API_VERSION+" "+COMM_MODULE_INFO;
	}
	
	void SetCommModuleInfo(String info){
		COMM_MODULE_INFO = info;
	}
}
