package beans;

public class UserAccount {

	   public static final String PERSON_CLIENT ="C";
	   public static final String PERSON_MANAGER = "M";
	   public static final String PERSON_REP = "R"; 
	   private String userName;
	   private String password;
	    
	 
	   public UserAccount() {
	        
	   }
	    
	   public String getUserName() {
	       return userName;
	   }
	 
	   public void setUserName(String userName) {
	       this.userName = userName;
	   }
	 
	   public String getPassword() {
	       return password;
	   }
	 
	   public void setPassword(String password) {
	       this.password = password;
	   }
}
