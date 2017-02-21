package upsc.api.test;

import android.test.AndroidTestCase;
import upsc.framework.api.UpscSIM;
import upsc.framework.api.UpscSIMEmulation;

public abstract class UPSCTestCase extends AndroidTestCase {
	
	UpscSIM m_upsc = null;
	
    public UPSCTestCase() {
        super();
    }   
	
    @Override
	public void setUp() throws Exception{
    	super.setUp();
    	m_upsc = UpscSIM.getInstance(getContext()); 
	}
	
	@Override
	public void tearDown() throws Exception{
		super.tearDown();
	}
	

}
