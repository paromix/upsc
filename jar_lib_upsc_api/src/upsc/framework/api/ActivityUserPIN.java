package upsc.framework.api;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.view.Window;
import android.widget.Button;
import android.widget.EditText;

/**
 * The public class of Activity.
 * Get PIN from user.
 */
public class ActivityUserPIN extends Activity {
	
	private static final String LOG_TAG = "ActivityUserPIN";
	
	@Override
    public void onCreate(Bundle savedInstanceState)
	{
    	super.onCreate(savedInstanceState);  
    	requestWindowFeature(Window.FEATURE_NO_TITLE);
    	setContentView(R.layout.user_pin);
    	
    	Button button = (Button)findViewById(R.id.key_pin_ok);
        button.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
            	Log.i(LOG_TAG, "OK BUTTON TOUCH");
            	EditText edit = (EditText)findViewById(R.id.text_key_pin);
            	String keyPin = edit.getText().toString();
            	Log.i(LOG_TAG, "KEY PIN : " + keyPin);
            }
        });
	}
}

