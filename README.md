[Link to the dataset website:by select Dataset then Entire Dataset then you can find the dataset file "UNSW_2018_IoT_Botnet_Dataset_1.csv" ](https://research.unsw.edu.au/projects/bot-iot-dataset)

Step 1: Prerequisites
1- Install Mininet:
Install Mininet 2.3.0 or higher on Ubuntu. Use the following commands to install it:
sudo apt update
sudo apt install mininet
2- Install Python 3.x and Required Libraries:
Ensure Python 3.x is installed, and install required libraries such as pandas, socket, csv, and json:
sudo apt install python3 python3-pip
pip3 install pandas
3- Clone the Repository:
Clone the project repository from GitHub:
git clone https://github.com/Shahadal22/Graduation-Project.git cd Graduation-Project
4- Install Ryu Controller:
Ryu is required for managing the network. Install it using the following commands:
sudo apt install python3-ryu

Step 2: Using the Dataset
1- Dataset File:
Locate the dataset file, typically named experiment.csv, in the repository directory or a specified folder.
2- 
3- Modify the Code to Load Dataset:
Ensure the dataset path in the code is correct. Open the Python script responsible for traffic generation (traffic_generator.py or similar) and verify the dataset file path:
df = pd.read_csv('path/to/experiment.csv', low_memory=False)
4- Prepare Dataset:
Ensure the dataset contains the following columns: login_times, power_consumption, network_reputation, traffic_pattern, requested_service_security, session_duration, hardware_security, data_security. Adjust as needed to match your project requirements.

Step 3: Running the Code in Mininet
1- Start Mininet:
Run Mininet with a predefined topology (TreeTopo or similar):
sudo python3 topology.py
2- Start Ryu Controllers:
Run the Ryu controllers in separate terminals. Replace controller1.py and controller2.py with the actual controller script names:
ryu-manager controller1.py
ryu-manager controller2.py
3- Generate Traffic:
Start the traffic generation script (e.g., traffic_generator.py):
sudo python3 traffic_generator.py
Monitor Logs:
•	Check the CSV logs generated during the experiment for results.
•	Use Mininet commands to interact with the virtual network:
pingall # Test connectivity 
iperf # Measure bandwidth

Step 4: Debugging and Validation
1- Ensure Dataset is Properly Loaded:
Verify the script reads the dataset without errors.
2- Check Controller Logs:
Look for errors or confirmation messages in the terminal where the Ryu controllers are running.
3- Analyze Results:
- Open the CSV log files (e.g., trust_0.8.csv) to evaluate trust values and decisions (Allowed/Blocked).
- Use these results to analyze network performance
