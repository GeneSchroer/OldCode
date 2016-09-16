package utils;

import java.sql.Connection;
import java.sql.Date;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

import beans.Client;
import beans.Employee;
import beans.MailingList;
import beans.Person;

public class RepresentativeUtils {

	public static List<Client> getClientList(Connection conn) throws SQLException {
		String sql = "select C.*, P.* from Client C, Person P where C.id=P.SSN";
		
		PreparedStatement pstm = conn.prepareStatement(sql);
		
		ResultSet rs = pstm.executeQuery();
		List<Client> list = new ArrayList<Client>();
		while(rs.next()){
			Client client = new Client(rs.getInt("SSN"), rs.getString("firstName"), rs.getString("lastName"), rs.getString("address"), rs.getInt("zipCode"), rs.getString("telephone"),
					rs.getString("email"), rs.getInt("rating"), rs.getString("creditCardNumber"));
			list.add(client);
		}
		return list;
	}

	public static void addClient(Connection conn, Client client) throws SQLException {
		String sql = "insert into Person(SSN, LastName, FirstName, Address, ZipCode, Telephone)"
				+" values(?, ?, ?, ?, ?, ?)";
		PreparedStatement pstm = conn.prepareStatement(sql);
		
		pstm.setInt		(1, client.getSSN());
		pstm.setString	(2, client.getLastName());
		pstm.setString	(3, client.getFirstName());
		pstm.setString	(4, client.getAddress());
		pstm.setInt		(5, client.getZipCode());
		pstm.setString	(6, client.getTelephone());
		pstm.executeUpdate();
		
		sql = "insert into Client(Email, Rating, CreditCardNumber, ID)"
				+" value(?, ?, ?, ?)";
		
		pstm = conn.prepareStatement(sql);
		pstm.setString(1, client.getEmail());
		pstm.setInt(2, client.getRating());
		pstm.setString(3, client.getCreditCardNumber());
		pstm.setInt(4, client.getId());
		pstm.executeUpdate();
	}

	public static Client findClient(Connection conn, int id) throws SQLException {
		String sql = "select * from Client where id = ?";
		PreparedStatement pstm = conn.prepareStatement(sql);
		pstm.setInt(1, id);
		ResultSet rs = pstm.executeQuery();
		
		if(rs.next()){
			String email 			= rs.getString("email");
			int rating 				= rs.getInt("rating");
			String creditCardNumber = rs.getString("creditCardNumber");
			int clientId			= rs.getInt("id");
		
			Person person 			= findPerson(conn, clientId);
			String lastName 		= person.getLastName();
			String firstName 		= person.getFirstName();
			String address 			= person.getAddress();
			int zipCode 			= person.getZipCode();
			String telephone 		= person.getTelephone();
			Client client 			= new Client(clientId, lastName,
					firstName, address, zipCode, telephone, email, rating, creditCardNumber);
			return client;
		}
		else
		
		
		return null;
	}
	public static Person findPerson(Connection conn, int PSSN) throws SQLException {
		String sql = "select P.* from Person P where P.SSN = ?";
			
			PreparedStatement pstm = conn.prepareStatement(sql);
			pstm.setInt(1, PSSN);
			ResultSet rs = pstm.executeQuery();
			
			if(rs.next()){
				int SSN = rs.getInt("SSN");
				String lastName = rs.getString("lastName");
				String firstName = rs.getString("firstName");
				String address = rs.getString("address");
				int zipCode = rs.getInt("zipCode");
				String telephone = rs.getString("telephone");
				Person person = new Person(SSN, lastName, firstName, address, 
					zipCode, telephone);
				return person;
			}
			else		
				return null;
		}

	public static void updateClient(Connection conn, Client client) throws SQLException {
		String sql = "update Person set LastName=?, FirstName=?, Address=?, ZipCode=?,"
				+	" Telephone=? where SSN=?";
			PreparedStatement pstm = conn.prepareStatement(sql);
			
			pstm.setString	(1, client.getLastName());
			pstm.setString	(2, client.getFirstName());
			pstm.setString	(3, client.getAddress());
			pstm.setInt		(4, client.getZipCode());
			pstm.setString	(5, client.getTelephone());
			pstm.setInt		(6, client.getId());
			pstm.executeUpdate();
			
			sql = "update Client set Email=?, Rating=?, CreditCardNumber=? where id = ?";
			pstm = conn.prepareStatement(sql);
			pstm.setString	(1, client.getEmail());
			pstm.setInt		(2, client.getRating());
			pstm.setString	(3, client.getCreditCardNumber());
			pstm.setInt		(4, client.getId());
			pstm.executeUpdate();
	}
	
	private static Integer getMostRecentOrderId(Connection conn) throws SQLException{
		
		String sql = "Select Id from Order by Id desc";
		PreparedStatement pstm = conn.prepareStatement(sql);
		ResultSet rs = pstm.executeQuery();
		if(rs.next())
			return rs.getInt("id");
		else 
			return null;
	}

	public static void deleteClient(Connection conn, int id) throws SQLException {
		String sql = "delete from Client where id = ?";
		PreparedStatement pstm = conn.prepareStatement(sql);
		pstm.setInt(1, id);
		pstm.executeUpdate();
		
		
		sql = "delete from Person where SSN = ?";
		pstm = conn.prepareStatement(sql);
		pstm.setInt(1, id);
		pstm.executeUpdate();
	}
	public static List<MailingList> getMailingList(Connection conn) throws SQLException{
			String sql = "select concat(P.FirstName, ' ',  P.LastName) as Name, C.Email, P.Address, L.City, L.State, L.ZipCode from Client C, Location L, Person P where P.ZipCode=L.ZipCode and P.SSN=C.Id order by P.LastName asc";
			PreparedStatement pstm = conn.prepareStatement(sql);
			
			ResultSet rs = pstm.executeQuery();
			List<MailingList> list = new ArrayList<MailingList>();
			while(rs.next()){
				MailingList ms = new MailingList(rs.getString("name"), rs.getString("email"), rs.getString("address"), rs.getString("city"), rs.getString("state"), rs.getInt("zipCode"));
				list.add(ms);
			}
			return list;
		}
}

