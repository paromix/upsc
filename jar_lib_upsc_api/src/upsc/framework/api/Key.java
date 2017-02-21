package upsc.framework.api;

class Key {
	Object m_wrapRef = null;
	
	void setReference(Object ref){
		m_wrapRef = ref;
	}
	
	Object getReference(){
		return m_wrapRef;
	}
}
