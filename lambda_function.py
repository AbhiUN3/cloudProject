import json
import boto3
import hashlib
import uuid
from botocore.exceptions import ClientError
import datetime
from datetime import datetime, date

# Initialize DynamoDB
dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
users_table = dynamodb.Table('Users')
tickets_table = dynamodb.Table('tickets')

status_check_path = '/status'
user_path = '/user'


def lambda_handler(event, context):
    http_method = event.get('httpMethod')
    path = event.get('path')


    if http_method == 'GET' and path == status_check_path:
            response = build_response(200, 'Service is operational')
    elif http_method == 'POST' and path == '/register':
        return register_user(event)
    elif http_method == 'POST' and path == '/login':
        return login_user(event)
    elif http_method == 'GET' and path == '/user':
        return get_user_by_id(event)
    elif http_method == 'GET' and path == '/users':
        return get_all_users()
    elif path == '/addTicket' and http_method == 'POST':
            response = add_ticket(json.loads(event['body']))
            return response
    elif http_method == 'GET' and path == '/tickets':
            return  get_tickets()
    elif path == '/updateTicket' and http_method == 'PUT':
        body = json.loads(event['body'])
        ticket_id = body['ticketid']
        updates = body.get('updates', {})  # The fields to update
        username = body.get('username')   # The user making the update
        return update_ticket(ticket_id, updates, username)
        
    else:
        return build_response(404, 'Route not found')

# Function for user registration
def register_user(event):
    try:
        body = json.loads(event.get('body'))
        username = body.get('username')
        password = body.get('password')
        user_type = body.get('user_type')

        if not username or not password or not user_type:
            return build_response(400, "All fields (username, password, user_type) are required.")
    
        # Hash the password before storing it
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        # Check if username already exists
        scan_response = users_table.scan(FilterExpression='username = :username', ExpressionAttributeValues={':username': username})
        if scan_response['Items']:
            return build_response(400, "Username already exists.")

        # Generate a unique user ID
        user_id = str(uuid.uuid4())

        # Save user to the database
        users_table.put_item(
            Item={
                'userid': user_id,
                'username': username,
                'password': hashed_password,
                'user_type': user_type
            }
        )
        return build_response(200, {
            'Message': 'User registered successfully!',
            'userid': user_id
        })

    except ClientError as e:
        print("DynamoDB Error:", e)
        return build_response(500, "An error occurred while processing the request.")
    except Exception as e:
        print("Error:", e)
        return build_response(500, "An error occurred while processing the request.")


#function for login
def login_user(event):
    try:
        body = json.loads(event.get('body'))
        username = body.get('username')
        password = body.get('password')

        if not username or not password:
            return build_response(400, "Both username and password are required.")

        # Hash the provided password for comparison
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        # Fetch user by username
        scan_response = users_table.scan(FilterExpression='username = :username', ExpressionAttributeValues={':username': username})
        users = scan_response.get('Items', [])

        if not users:
            return build_response(401, "Invalid username or password.")

        user = users[0]

        # Check if the password matches
        if user['password'] == hashed_password:
            return build_response(200, {
                'Message': 'Login successful!',
                'userid': user['userid'],
                'username': user['username'],
                'user_type': user['user_type']
            })
        else:
            return build_response(401, "Invalid username or password.")

    except ClientError as e:
        print("DynamoDB Error:", e)
        return build_response(500, "An error occurred while processing the request.")
    except Exception as e:
        print("Error:", e)
        return build_response(500, "An error occurred while processing the request.")

# Function to get user by ID
def get_user_by_id(event):
    try:
        user_id = event['queryStringParameters']['userid']

        if not user_id:
            return build_response(400, "User ID is required.")

        response = users_table.get_item(Key={'userid': user_id})

        if 'Item' not in response:
            return build_response(404, "User not found.")

        user = response['Item']
        user.pop('password', None)

        return build_response(200, user)

    except ClientError as e:
        print("DynamoDB Error:", e)
        return build_response(500, "An error occurred while processing the request.")
    except Exception as e:
        print("Error:", e)
        return build_response(500, "An error occurred while processing the request.")

# Function to get all users
def get_all_users():
    try:
        response = users_table.scan()

        users = response.get('Items', [])
        for user in users:
            user.pop('password', None)  # Remove sensitive password information

        return build_response(200, users)

    except ClientError as e:
        print("DynamoDB Error:", e)
        return build_response(500, "An error occurred while processing the request.")
    except Exception as e:
        print("Error:", e)
        return build_response(500, "An error occurred while processing the request.")

#creat ticket function

def add_ticket(event_body):
    try:
        ticket_id = str(uuid.uuid4())
        current_time = datetime.utcnow().isoformat()
        
        ticket = {
            'ticketid': ticket_id,
            'ticketTitle': event_body['ticketTitle'],
            'ticketDescription': event_body['ticketDescription'],
            'userId': event_body['userId'],
            'userName': event_body['userName'],
            'assignedTo': event_body['assignedTo'],
            #'assignedId': event_body['assignedId'],
            'priority': event_body['priority'],
            'createdBy': event_body['createdBy'],  # userId of the creator
            'updateBy': event_body['createdBy'],
            'createdTime': current_time,
            'updatedTime': current_time,
            'ticketStatus': event_body.get('status', 'Open'),  # Default status
            
            'comments' :event_body.get('comments')

        }

        tickets_table.put_item(Item=ticket)
        return build_response(200, {'message': 'Ticket created successfully', 'ticket': ticket})
    except Exception as e:
        print('Error:', e)
        return build_response(500, {'message': 'Failed to create ticket', 'error': str(e)})

#update ticket
def update_ticket(ticket_id, updates, username):
    try:
        # Validate input
        if not updates:
            return build_response(400, {'message': 'No fields to update provided'})

        # Fetch the ticket
        response = tickets_table.get_item(Key={'ticketid': ticket_id})
        if 'Item' not in response:
            return build_response(404, {'message': 'Ticket not found'})
        
        current_ticket = response['Item']
        current_time = datetime.utcnow().isoformat()

        # Build the update expression
        update_expression = "SET updatedTime = :updatedTime, updateBy = :updateBy"
        expression_attribute_values = {
            ':updatedTime': current_time,
            ':updateBy': username
        }


        # Handle comments specifically
        if 'comments' in updates:
            new_comment = updates.pop('comments')  # Extract the new comment
            if not isinstance(new_comment, dict) or 'comment' not in new_comment or 'username' not in new_comment:
                return build_response(400, {'message': 'Invalid comment format'})
            #update_expression += ", comments = list_append(comments, :newComment)"
            #expression_attribute_values[':newComment'] = [new_comment]  # Add as a list to append

             # Add timestamp to the new comment
            new_comment_with_timestamp = {
                'comment': new_comment['comment'],
                'username': new_comment['username'],
                'timestamp': current_time
            }


            # Check if the `comments` field exists; if not, initialize it as an empty list
            existing_comments = current_ticket.get('comments', [])
            existing_comments.append(new_comment_with_timestamp)

            # Update the expression for comments
            update_expression += ", comments = :comments"
            expression_attribute_values[':comments'] = existing_comments


        #add other fields from the updates dictionary
        for key, value in updates.items():
            update_expression += f", {key} = :{key}"
            expression_attribute_values[f":{key}"] = value


         # Log for debugging
        #print("Update Expression:", update_expression)
        #print("Expression Attribute Values:", expression_attribute_values)
        
        # Update the ticket in DynamoDB
        tickets_table.update_item(
            Key={'ticketid': ticket_id},
            UpdateExpression=update_expression,
            ExpressionAttributeValues=expression_attribute_values,
            ReturnValues="UPDATED_NEW"
        )
       # updated_ticket = tickets_table.get_item(Key={'ticketid': ticket_id}).get('Item', {})

        return build_response(200, {
            'message': 'Ticket updated successfully',
            'updatedFields': expression_attribute_values
        })
    except Exception as e:
        print('Error:', e)
        return build_response(500, {'message': 'Failed to update ticket', 'error': str(e)})




def get_tickets():
    try:
        response = tickets_table.scan()
        return build_response(200, {'tickets': response['Items']})
    except Exception as e:
        print('Error:', e)
        return build_response(500, {'message': 'Failed to fetch tickets', 'error': str(e)})

class DecimalEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Decimal):
            # Check if it's an int or a float
            if obj % 1 == 0:
                return int(obj)
            else:
                return float(obj)
        # Let the base class default method raise the TypeError
        return super(DecimalEncoder, self).default(obj)


# Helper function to build responses
def build_response(status_code, message):
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",  # Allow all origins (use specific domain in production)
            "Access-Control-Allow-Methods": "OPTIONS,POST,GET,PUT",  # Allowed methods
            "Access-Control-Allow-Headers": "Content-Type"       # Allowed headers
        },
        "body": json.dumps(message, cls=DecimalEncoder)
    }


