package upsc.framework.api;

/**
 * The public class of exception management. 
 */
public class UPSCException extends Exception {

	private static final long serialVersionUID = -5094255701828749339L;

	private String m_reason = null;
	
	public UPSCException(){
		m_reason = "";
	}
	
	public UPSCException(String reason){
		m_reason = reason;
	}
	
	public String getReason(){
		return m_reason;
	}
}
